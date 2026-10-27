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
| Standards | `OWASP API10:2023`, `OWASP ASVS v5.0.0-2.2.1` |
| Tags | `input-validation`, `injection`, `fuzzing` |
| Prerequisites | none |
| Needs | - |
| Parameters | none |
| Tool | `schemathesis` ([`external_tools.schemathesis`](../../../03-reference/01-configuration.md#external_tools)) |

<!-- [[[end]]] -->

**Tool:** Schemathesis (Python, the `[schemathesis]` extra). **Same guarantee:** 3.1 input validation.

## 1. Guarantee

Every input is validated against its type, format, range and pattern before the business logic. A PASS promises
Schemathesis found no operation that mishandles a generated input. The threat (OWASP API10:2023, CWE-20): a 500 on a
bad input (the input reached the logic), an invalid input accepted, or a non-conformant response. ASVS v5.0.0-2.2.1.

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

`schemathesis run <spec> --base-url <base> --checks not_a_server_error,negative_data_rejection,response_schema_conformance`
generates requests per operation (bounded by `max_examples`), unauthenticated. Effect `STRESSES_TARGET` (many
generated requests), run last. Unauthenticated: the write requests it generates are refused, so nothing is created.

## 6. Oracle (`input_validated`)

| Case | Outcome / detail | Confidence |
|---|---|---|
| no operation fails a check | `ENFORCED/INPUT_VALIDATED` | - |
| an operation fails a check (500 on a bad input, invalid input accepted, non-conformant response) | `VIOLATION/INPUT_NOT_VALIDATED` (one per operation, up to 20 reported) | FIRM (the tool observed it) |
| the tool could not connect / timed out | ERROR (the base class handles it) | - |

## 7. Outcomes

SKIP without Schemathesis. FAIL on any failing operation; PASS when every generated input is handled.

## 8. Findings

"Input not validated: `<METHOD> <path>`", with the failing check's detail (and a curl to reproduce, from
Schemathesis); `evidence_ref` the tool output artifact.

## 9. Effects on the target

`STRESSES_TARGET`: many generated requests, unauthenticated (no data created). Runs last.

## 10. Per gateway

Independent of the gateway: the validation is the application's; Schemathesis addresses the API through the base URL.

## 11. Configuration

Under `external_tools.schemathesis`: `enabled`, `timeout_seconds` (required when enabled), `max_examples` (generated
cases per operation, default 5).

## 12. Validation

Runs of 2026-10-23:

| Lab | Status | Basis |
|---|---|---|
| crAPI + Kong | **FAIL**, 20 findings | e.g. `POST /identity/api/auth/v3/check-otp` returns 500 on a generated input (a leaked exception, not a clean 400); real validation/error-handling gaps |
| Forgejo + Kong, Forgejo + APISIX | **PASS** | no operation returns a 500 or accepts an invalid input; generated invalid inputs are rejected |

Rule 9, both sides proven agnostically: VIOLATION on crAPI (real 500s), ENFORCED on Forgejo. Fast (crAPI 4.7 s,
Forgejo 12.6 s at `max_examples` 1-2).

## 13. Remediation

Validate every input against its type, format, range and pattern (allow-list) at the edge, returning a clean 400 on
a bad input, and never a 500 (OWASP API10:2023, ASVS v5.0.0-2.2.1).

## 14. Limitations

- Unauthenticated, and it stays so (2026-10-27): the validation of authenticated-only operations, and of write
  bodies, is never exercised, so a validation gap behind the credential is not seen. Deep injection confirmation
  (sqlmap, NoSQLMap, Dalfox, commix) is not planned either.
- Bounded by `max_examples`: a validation gap that needs a specific generated value may be missed at a low setting.
- Schemathesis flags a 500 or a non-conformant response; whether a flagged input actually executes an injection is
  outside what this test can say: it reports a suspicious response, never a confirmed injection.

## 15. Sources

- OWASP API10:2023 Unsafe Consumption of APIs / input validation: https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/
- OWASP ASVS v5.0.0-2.2.1 (input validated against expectations): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md
- CWE-20 Improper Input Validation: https://cwe.mitre.org/data/definitions/20.html
- Schemathesis: https://schemathesis.readthedocs.io/
