# ext.3.1.schemathesis Input Validation

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/external_tests/ext_test_3_1_input_validation_schemathesis.py`](../../../../src/external_tests/ext_test_3_1_input_validation_schemathesis.py),
> [`src/connectors/schemathesis.py`](../../../../src/connectors/schemathesis.py) · **Verified:** 2026-10-23

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("ext.3.1.schemathesis", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `ext.3.1.schemathesis` |
| Name | Input Validation (Schemathesis) |
| Domain | 3 - Data Integrity |
| Priority / strategy | P2 / BLACK_BOX |
| Effect | STRESSES_TARGET |
| CWE | CWE-20 |
| Standards | `OWASP ASVS v5.0.0-2.2.1`, `NIST SP 800-53r5, Section 3.19` |
| Tags | `input-validation`, `injection`, `fuzzing` |
| Prerequisites | none |
| Needs | - |
| Parameters | none |
| Tool | `schemathesis` ([`external_tools.schemathesis`](../../../03-reference/01-configuration.md#external_tools)) |

<!-- [[[end]]] -->

**Tool:** Schemathesis (Python, the `[schemathesis]` extra). **Same guarantee:** 3.1 input validation.

## 1. Guarantee

Every input is validated against its type, format, range and pattern before the business logic. A PASS promises
Schemathesis found no operation that mishandles a generated input. The threat (CWE-20, ASVS v5.0.0-2.2.1, NIST SP
800-53r5 SI-10): a 500 on a bad input (the input reached the logic), an invalid input accepted, or a non-conformant
response. The OWASP API Top 10 2023 has no category for the validation of a client's input (API10:2023 is the API's
trust in data it consumes from third-party APIs, which this test does not exercise), so the guarantee rests on the
three references above.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 3.1) |
|---|---|
| `input_validated` | Schemathesis generates valid and invalid inputs from the spec and runs `not_a_server_error`, `negative_data_rejection`, `response_schema_conformance` |
| left out | the deep injection confirmation (sqlmap, NoSQLMap, Dalfox, commix, SSTImap) and an authenticated run; neither is planned (2026-10-27) |

## 3. Inputs

The OpenAPI specification (`target.get_openapi_source()`, a URL or local file), the base URL, and
`target.tls.ca_bundle`. `external_tools.schemathesis.max_examples` bounds the generated cases per operation. No
credential is injected.

## 4. Preconditions and reference responses

Schemathesis must be installed (else SKIP). No reference responses: the tool's own checks are the oracle (rule 11).

## 5. Probes

`schemathesis run <spec> --base-url <base><base path> --data-generation-method all --checks not_a_server_error,negative_data_rejection,response_schema_conformance`
generates valid and invalid requests per operation (bounded by `max_examples`), unauthenticated. The base URL
carries the specification's own base path (Forgejo's `/api/v1`), because Schemathesis takes the base path from the
base URL and drops the one in the specification. Effect `STRESSES_TARGET` (many
generated requests), run last. Unauthenticated: the write requests it generates are refused, so nothing is created.

## 6. Oracle (`input_validated`)

| Case | Outcome / detail | Confidence |
|---|---|---|
| no operation fails a check, and at least one was checked | `ENFORCED/INPUT_VALIDATED` | - |
| an operation fails a check (500 on a bad input, invalid input accepted, non-conformant response) | `VIOLATION/INPUT_NOT_VALIDATED` (one per operation, up to 20 reported) | FIRM (the tool observed it) |
| an operation's only failure is an unavailable backend (the failure quotes only `502`, `503` or `504`) | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE`, no finding | - |
| Schemathesis reports an operation as errored or skipped | `NOT_VERIFIABLE/OPERATION_NOT_CHECKED` | - |
| no operation was checked at all | `NOT_VERIFIABLE/NOTHING_CHECKED` | - |
| the tool could not connect / timed out | ERROR (the base class handles it) | - |

## 7. Outcomes

SKIP without Schemathesis. FAIL on any failing operation; PASS when at least one operation was checked and none
failed (`partial` when some could not be judged); INCONCLUSIVE when nothing could be checked.

## 8. Findings

"Input not validated: `<METHOD> <path>`", with the failing check's detail (and a curl to reproduce, from
Schemathesis); `evidence_ref` the tool output artifact.

## 9. Effects on the target

`STRESSES_TARGET`: many generated requests, unauthenticated, and they include the writes the specification
declares. **Whether data is created depends on the target, not on this test**: on the three labs nothing was, because
every operation served without a credential there is a `GET` (measured by test 1.1 on 2026-10-29, 78 findings, all
`GET`), but an API with an unauthenticated write will have it exercised. The declaration stays `STRESSES_TARGET`
because that is the last slot in the run order (rule 7) and the vocabulary has no value that says both; an operator
who cannot accept a write on the target disables the external tools (`external_tools.enabled: false`).

## 10. Per gateway

Independent of the gateway: the validation is the application's; Schemathesis addresses the API through the base URL.

## 11. Configuration

Under `external_tools.schemathesis`: `enabled`, `timeout_seconds` (required when enabled), `max_examples` (generated
cases per operation, default 5).

## 12. Validation

Runs of 2026-11-04:

| Lab | Status | Basis |
|---|---|---|
| crAPI + Kong | **FAIL**, 3 findings | `POST /identity/api/auth/v2/check-otp` and `/v3/check-otp` answer `500` on a generated input (a leaked exception), and `GET /workshop/api/shop/orders/{order_id}` answers outside crAPI's own schema. 15 more operations answered only `503`: `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| Forgejo + Kong | **PASS** | 469 operations listed, none failing with valid or invalid data |
| Forgejo + Kong, a second run the same day, same configuration | **FAIL**, 1 finding | `GET /api/v1/users/search` answered `200` to an input Schemathesis generated as invalid (`negative_data_rejection`, "Accepted negative data"): the inputs are generated at random on every run, so this one was not drawn in the first |

**What these runs corrected** (an external audit, 2026-11-03). On both Forgejo labs the base URL lacked `/api/v1`,
so every generated request missed the API: measured with Schemathesis limited to `GET`, all 241 operations answered
only `4xx` before the fix and 142 after it (the rest are reached; the 142 need a credential this unauthenticated
test does not carry). The test reported PASS throughout. On crAPI, 24 of the 27 failures of 2026-11-03 were Kong's
`503` once its health check had marked the backend unhealthy, each reported as a finding; and only valid data was
generated, so `negative_data_rejection` never had an invalid request to judge.

Rule 9: VIOLATION on crAPI (real `500`s), ENFORCED on Forgejo, `UPSTREAM_UNAVAILABLE` on crAPI. Not seen:
`OPERATION_NOT_CHECKED` and `NOTHING_CHECKED`.

## 13. Remediation

Validate every input against its type, format, range and pattern (allow-list) at the edge, returning a clean 400 on
a bad input, and never a 500 (CWE-20, ASVS v5.0.0-2.2.1, NIST SP 800-53r5 SI-10).

## 14. Limitations

- **The inputs are generated at random on every run** (Hypothesis), so the same target and configuration can give
  different findings from one run to the next: on 2026-11-04 Forgejo + Kong gave PASS, then one finding on
  `GET /api/v1/users/search`. A finding is a real request the target answered (its reproduction is in the
  artifact); a PASS says only that the inputs drawn in that run were all handled. Raising `max_examples` draws more.
- Each generated request is given `request_timeout_seconds` (default 5) to answer; a slower one counts as failed.
- Unauthenticated, and it stays so (2026-10-27): the validation of authenticated-only operations, and of write
  bodies, is never exercised, so a validation gap behind the credential is not seen. Deep injection confirmation
  (sqlmap, NoSQLMap, Dalfox, commix) is not planned either.
- Bounded by `max_examples`: a validation gap that needs a specific generated value may be missed at a low setting.
- Schemathesis flags a 500 or a non-conformant response; whether a flagged input actually executes an injection is
  outside what this test can say: it reports a suspicious response, never a confirmed injection.

## 15. Sources

- NIST SP 800-53 Rev.5 SI-10 (information input validation): https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home
- OWASP ASVS v5.0.0-2.2.1 (input validated against expectations): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md
- CWE-20 Improper Input Validation: https://cwe.mitre.org/data/definitions/20.html
- Schemathesis: https://schemathesis.readthedocs.io/
