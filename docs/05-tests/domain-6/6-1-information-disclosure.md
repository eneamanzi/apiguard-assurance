# 6.1 Error and Information Disclosure

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_6/test_6_1_information_disclosure.py`](../../../src/tests/domain_6/test_6_1_information_disclosure.py), [`src/tests/helpers/response_inspector.py`](../../../src/tests/helpers/response_inspector.py)

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

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 6.1) |
|---|---|
| `no_stack_trace` | "stack trace detection on provoked errors": a malformed request leaks no exception, path, class or framework version |
| `no_debug_field` | "debug field detection in a normal response": no debug-named field (`_debug`, `_sql...`, `debugInfo`, `stackTrace`, `shardKey`, ...) at any depth of a served JSON body |
| `no_leaky_header` | "header information leakage": no `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, and no `Server` or `Via` naming a version; other internal `X-*` headers and `X-Kong-*` are not judged |
| left out | authentication-error enumeration (test 1.7); the correlation-ID check (not reproducible from outside); the methodology's other error probes (a type mismatch, a missing required field, an oversized payload) and the consistency of error verbosity across error kinds |

### 2.2 Preconditions and reference responses

user_a is required (GREY_BOX). No reference responses: the detection is on the response content itself.

### 2.3 Probes

For each sampled endpoint, a normal GET (debug fields in the body, leaky headers). Malformed-JSON requests to the
documented writes in turn, declared `Content-Type: application/json` so that the server's JSON parser runs, until one
is parsed into an error (a `400`, `422` or server error), at most five. The request's own URL
and path are taken out of the error body before it is scanned (an echoed `/app/...` path is not the server's).
CHANGES_DATA, for the reason in section 10.

## 3. Oracle

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

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("6.1", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | judged by the oracle above: a `500` is the error this test provokes, and its body is where a stack trace or a debug field shows: it is examined. |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("6.1", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 15 of 15 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `no_stack_trace/VIOLATION/STACK_TRACE/FIRM` | forgejo-kong: a temporary route POST ~/api/v1/orgs$ (the first error probe) answers 500 itself with a body holding 'Caused by: java.lang.NullPointerException' | OK |
| `no_stack_trace/ENFORCED/NO_STACK_TRACE` | forgejo-kong: the lab as built: POST /api/v1/orgs is refused 403 by the token's scope, then POST /api/v1/markup parses the malformed body and answers 422 with no marker | OK |
| `no_stack_trace/NOT_VERIFIABLE/ERROR_NOT_PROVOKED` | forgejo-kong: a temporary regex route ~/api/v1/ for POST, PUT and PATCH whose pre-function answers 415 to a request whose body is the test's malformed JSON and passes every other request (the engine's login) to Forgejo, so none of the five writes parses it | OK |
| `no_stack_trace/NOT_APPLICABLE/NO_ERROR_PROBE` | forgejo-kong: the run reads a local copy of Forgejo's specification whose only path is GET /orgs (no write documented) | OK |
| `no_debug_field/VIOLATION/DEBUG_FIELD/FIRM` | forgejo-kong: a temporary route GET ~/api/v1/orgs$ (the sampled read) answers 200 itself with the object {"_debug": "info", "data": 1} | OK |
| `no_debug_field/ENFORCED/CLEAN` | forgejo-kong: the lab as built: GET /api/v1/orgs is served an array of organization objects with no debug-named field | OK |
| `no_debug_field/NOT_VERIFIABLE/NO_JSON_OBJECT` | forgejo-kong: a temporary route GET ~/api/v1/orgs$ answers 200 itself with the text/plain body 'ok', so no sampled read is served a JSON object | OK |
| `no_debug_field/NOT_APPLICABLE/NO_READ_ENDPOINT` | forgejo-kong: the run reads a local copy of Forgejo's specification whose only path is POST /markup (no GET or HEAD documented) | OK |
| `no_leaky_header/VIOLATION/LEAKY_HEADER/CERTAIN` | forgejo-kong: a temporary route GET ~/api/v1/orgs$ answers 200 itself with the header X-AspNet-Version: 4.0.30319 | OK |
| `no_leaky_header/VIOLATION/LEAKY_HEADER/FIRM` | forgejo-kong: a temporary route GET ~/api/v1/orgs$ whose post-function (header_filter, after the service's response-transformer) sets X-Powered-By: Express on Forgejo's answer | OK |
| `no_leaky_header/ENFORCED/CLEAN` | forgejo-kong: the lab as built: the sampled answer carries no leaky header (the service's response-transformer removes X-Powered-By) | OK |
| `no_leaky_header/NOT_APPLICABLE/NO_READ_ENDPOINT` | forgejo-kong: the run reads a local copy of Forgejo's specification whose only path is POST /markup (no GET or HEAD documented) | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: a temporary route on the sampled read GET ~/api/v1/orgs$ answers 503 itself: no_debug_field and no_leaky_header have no usable answer | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: a temporary route on the sampled read GET ~/api/v1/orgs$ answers 429 itself | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: a temporary route on the sampled read GET ~/api/v1/orgs$ sleeps 7 s before proxying, past the run's read timeout of 5 s | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("6.1", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- What counts as a stack trace is a list of markers (`src/tests/data/inspector_patterns.py`) and a file-system path
  that starts a value (`"/app/main.py"`, `/usr/src/...`): a path inside a URL (`https://host/home/...`) and the
  generic `app/` and `at /` no longer count.
- An answer of an unavailable or throttled backend (`503`, `429`), or no answer, is not looked at for debug fields or
  headers; with no usable answer the two sub-tests are `NOT_VERIFIABLE` with the reason of the answers left out
 .
- Detection is by keyword/field-name/header-name heuristics: an oddly-shaped leak is missed, a benign match is a
  FIRM (not CERTAIN) finding.
- The error is provoked with malformed JSON only, on up to five writes; a leak that needs a specific input shape is
  not triggered.
- A debug-named field documented in the operation's response schema is still reported (FIRM): the names are a list,
  not a comparison with the specification.
- The sample is one endpoint per service: a leak on an un-sampled endpoint of the same service is missed.

## 6. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- OWASP ASVS v5.0.0-13.4.2 (debug modes disabled), v5.0.0-13.4.6 (no version disclosure): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x22-V13-Configuration.md
- OWASP ASVS v5.0.0-16.5.1 (generic error message): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
- CWE-209 Generation of Error Message Containing Sensitive Information: https://cwe.mitre.org/data/definitions/209.html

## 7. Inputs

A sample of documented operations, one per service prefix (`src/tests/helpers/sampling.py`), for the normal-response
checks; up to five documented writes for the error provocation (malformed JSON), without path parameters first. user_a to reach authenticated
endpoints. The response-inspection helpers do the detection.

## 8. Outcomes

SKIP without user_a or a surface. FAIL on any leak; PASS when the provoked error and the sampled responses are
clean.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("6.1")) ]]] -->

- "Response carries a leaky header: <names>"
- "Response carries a debug field: <names>"
- "Error response leaks internal detail: <method> <path>"

<!-- [[[end]]] -->

Each has, as its proof, the response of the endpoint the finding names as its example. Each cites its own requirement: the stack trace ASVS v5.0.0-16.5.1, the debug field 13.4.2
(debug modes disabled), the header 13.4.6.

## 10. Effects on the target

`CHANGES_DATA`: sampled reads plus up to five requests with a malformed body (`{"apiguard": "unterminated`) to the
shortest documented write operations. No JSON parser can build an object from it, so a `POST` creates nothing, and
on the three labs nothing was created or changed. The declaration is `CHANGES_DATA` all the same, because on a
target whose shortest documented write is a `PUT` on an existing object, a server that read an unparseable body as
an empty one would replace that object: what the test sends is a write, and the effects table an operator reads
before a production run says what is sent, not what a well-behaved server does with it.

## 11. Per gateway

Independent of the adapter: the leak is the backend's (a stack trace, a debug field) or the stack's (a version
header, which the gateway should strip).

## 12. Configuration

None.

## 13. Remediation

Return a generic message with a correlation ID to the client and keep the detail in the server logs (ASVS
v5.0.0-16.5.1); strip version and `X-Powered-By` headers at the gateway (v5.0.0-13.4.6); remove debug fields from
production responses.
