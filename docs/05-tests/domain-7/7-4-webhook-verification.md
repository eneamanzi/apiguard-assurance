# 7.4 Webhook Signature Verification

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_7/test_7_4_webhook_verification.py`](../../../src/tests/domain_7/test_7_4_webhook_verification.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("7.4", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `7.4` |
| Name | Webhook Signature Verification |
| Domain | 7 - Business Logic and Sensitive Flows |
| Priority / strategy | P1 / BLACK_BOX |
| Effect | CHANGES_DATA |
| CWE | CWE-347 |
| Standards | `OWASP API10:2023` |
| Tags | `business-logic`, `webhook`, `authenticity` |
| Prerequisites | none |
| Needs | `webhook_endpoint` |
| Parameters | [`tests.domain_7.test_7_4`](../../03-reference/01-configuration.md#testsdomain_7test_7_4) |

<!-- [[[end]]] -->

**Same group:** tests `7.1`, `7.2`, `7.3` (business logic and advanced threats).

## 1. Guarantee

A webhook receiver authenticates a delivery before acting on it: it verifies an HMAC signature over the raw body. A
PASS promises the endpoint rejected an unsigned and a wrongly signed delivery. The threat (OWASP API10:2023, unsafe
consumption of an external service; CWE-347): without verification anyone who can reach the endpoint forges events.

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 7.4) |
|---|---|
| `absent_signature_rejected` | "a delivery with no signature must be rejected" |
| `invalid_signature_rejected` | "a delivery with a wrong signature must be rejected" |
| left out | **replay protection** (timestamp window, event-ID dedup): not judgeable from the answer, see Limitations; the **blind-callback** case: it needs an out-of-band listener the tool controls, which is not built and not planned; constant-time comparison is not observable from outside |

### 2.2 Preconditions and reference responses

**Positive control:** when `signing_secret` is set, a *validly* signed delivery is sent first. A rejection of the
forged deliveries is evidence only when that valid one was accepted (`2xx`). If even the valid one is rejected, the
endpoint refuses every delivery (down, or auth elsewhere): both sub-tests are `NOT_VERIFIABLE/REJECTS_ALL`. Without
the secret, or when the valid delivery gets no usable answer (none, `5xx`, `429`), a rejection is
`NOT_VERIFIABLE/SIGNATURE_NOT_CONFIRMED`, and a note says how to confirm it: a wrong path (404) or a credential
required elsewhere (401) would be rejected the same way. An accepted forged delivery is a violation with or without
the control.

### 2.3 Probes

Up to three deliveries of the same raw body: (optionally) validly signed, then unsigned, then wrongly signed. Effect
`CHANGES_DATA`: a processed webhook may change data (a rejected one does not); announce it on a shared target.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("7.4")) ]]] -->

**`absent_signature_rejected`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the unsigned delivery answered `2xx`: accepted, which does not show it was acted on | `VIOLATION/UNSIGNED_ACCEPTED` | FIRM |
| the unsigned delivery refused (`400`, `401`, `403`, ...), and a validly signed delivery sent after it accepted | `ENFORCED/SIGNATURE_REQUIRED` | - |
| the unsigned delivery refused, and no validly signed delivery accepted (no secret, or no usable answer to it) | `NOT_VERIFIABLE/SIGNATURE_NOT_CONFIRMED` | - |
| the unsigned delivery refused, and the validly signed delivery refused too | `NOT_VERIFIABLE/REJECTS_ALL` | - |
| the unsigned delivery answered neither `2xx` nor a refusal (a redirect, `404`, `405`) | `NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | - |

**`invalid_signature_rejected`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the wrongly signed delivery answered `2xx`: accepted, which does not show it was acted on | `VIOLATION/BAD_SIGNATURE_ACCEPTED` | FIRM |
| the wrongly signed delivery refused (`400`, `401`, `403`, ...), and a validly signed delivery sent after it accepted | `ENFORCED/SIGNATURE_REQUIRED` | - |
| the wrongly signed delivery refused, and no validly signed delivery accepted (no secret, or no usable answer to it) | `NOT_VERIFIABLE/SIGNATURE_NOT_CONFIRMED` | - |
| the wrongly signed delivery refused, and the validly signed delivery refused too | `NOT_VERIFIABLE/REJECTS_ALL` | - |
| the wrongly signed delivery answered neither `2xx` nor a refusal (a redirect, `404`, `405`) | `NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | - |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("7.4", page=cog.inFile)) ]]] -->

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

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("7.4", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 14 of 14 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `absent_signature_rejected/VIOLATION/UNSIGNED_ACCEPTED/FIRM` | forgejo-kong: webhook_endpoint set to the prefix route /review-served, whose pre-function answers 200 to any request: the unsigned delivery is accepted | OK |
| `absent_signature_rejected/ENFORCED/SIGNATURE_REQUIRED` | forgejo-kong: webhook_endpoint set to a temporary Kong route that answers 204 to a delivery with a non-zero X-Sig and 401 to the others, with a signing secret: unsigned refused 401, the valid delivery after it accepted | OK |
| `absent_signature_rejected/NOT_VERIFIABLE/SIGNATURE_NOT_CONFIRMED` | forgejo-kong: webhook_endpoint set to POST /api/v1/markdown, no signing secret: Forgejo answers 401 (it requires a token there) and no positive control runs | OK |
| `absent_signature_rejected/NOT_VERIFIABLE/REJECTS_ALL` | forgejo-kong: webhook_endpoint set to POST /api/v1/markdown with a signing secret: Forgejo answers 401 to the unsigned, the wrongly signed and the validly signed delivery alike | OK |
| `absent_signature_rejected/NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | forgejo-kong: webhook_endpoint set to POST /api/v1/zqxv-validation-webhook, a path Forgejo does not have: every delivery answers 404, neither 2xx nor a refusal | OK |
| `invalid_signature_rejected/VIOLATION/BAD_SIGNATURE_ACCEPTED/FIRM` | forgejo-kong: same run as the unsigned case: the route /review-served answers 200 to the delivery signed with 64 zeros | OK |
| `invalid_signature_rejected/ENFORCED/SIGNATURE_REQUIRED` | forgejo-kong: same run as the unsigned case: the temporary receiver answers 401 to X-Sig of 64 zeros, then 204 to the validly signed delivery | OK |
| `invalid_signature_rejected/NOT_VERIFIABLE/SIGNATURE_NOT_CONFIRMED` | forgejo-kong: same run as the unsigned case: POST /api/v1/markdown, no signing secret, Forgejo answers 401 | OK |
| `invalid_signature_rejected/NOT_VERIFIABLE/REJECTS_ALL` | forgejo-kong: same run as the unsigned case: POST /api/v1/markdown with a signing secret, every delivery answered 401 | OK |
| `invalid_signature_rejected/NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | forgejo-kong: same run as the unsigned case: a path Forgejo does not have answers 404 to the wrongly signed delivery | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: webhook_endpoint set to /api-zqxv0074, matched by the temporary route ~/api[-.]?zqxv[0-9a-f]+$ answering 503: both deliveries 503 | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: webhook_endpoint set to /api-zqxv0074, matched by the temporary route answering 429: both deliveries 429 | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: webhook_endpoint set to /api-zqxv0074, matched by the temporary route answering 500: both deliveries 500 | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: webhook_endpoint set to /api-zqxv0074, matched by the temporary route sleeping 7 s, and the run's read timeout is 5 s: both deliveries get no answer | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("7.4", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- Only the inbound-verification case is tested. Constant-time comparison is not observable from outside.
- **Replay protection is not judgeable from the answer.** The test could send the same signed delivery twice, but a
  `2xx` to the second proves nothing: a receiver that recognises the duplicate and ignores it (idempotent handling)
  answers `2xx` too. A delivery that is
  validly signed but old, which must be refused, can be built only with a scheme that signs a timestamp, which
  `signature_format` does not support (next item). So a receiver that verifies its HMAC correctly but accepts a
  replayed delivery still passes here.
- The blind-callback case (the target calling a URL of ours) needs an out-of-band listener the tool controls, which
  is not built and not planned.
- Only the `{signature}` placeholder is supported in `signature_format`; schemes that sign a timestamp+body tuple
  need an extension.
- Only a hex HMAC-SHA256 over the raw body can be built (`signature_format`): a receiver expecting base64 (Shopify's scheme) refuses the valid delivery too, `REJECTS_ALL`.

## 6. Sources

- OWASP API10:2023 Unsafe Consumption of APIs: https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/
- OWASP Webhook Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Webhook_Security_Cheat_Sheet.html
- CWE-347 Improper Verification of Cryptographic Signature: https://cwe.mitre.org/data/definitions/347.html

## 7. Inputs

`webhook_endpoint` (no default): `path`, `method` (default `POST`), the `body` payload, the `signature_header` name,
an optional `signing_secret` (a `${VAR}` env reference, for the valid-signature positive control), and the
`signature_format` (default `{signature}`; e.g. `sha256={signature}` for GitHub). `{signature}` is the lowercase hex
HMAC-SHA256 of the raw body.

## 8. Outcomes

SKIP without `webhook_endpoint`. FAIL when a forged or unsigned delivery is accepted; PASS when both are rejected
(with a note if no positive control ran).

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("7.4")) ]]] -->

- "Webhook accepted without a signature: <method> <path>"
- "Webhook accepted with an invalid signature: <method> <path>"

<!-- [[[end]]] -->

`evidence_ref` the accepted delivery.

## 10. Effects on the target

`CHANGES_DATA`: deliveries to the receiver (rejected ones change nothing; an accepted forged one would be the
finding).

## 11. Per gateway

Independent of the adapter: the receiver is probed from outside.

## 12. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("7.4", page=cog.inFile)) ]]] -->

Section [`tests.domain_7.test_7_4`](../../03-reference/01-configuration.md#testsdomain_7test_7_4) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `webhook_endpoint` | object \| null | none, **needed to run** | The webhook receiver to probe for signature verification. No default: unset, the engine records the test as SKIP before it runs. |
| `webhook_endpoint.path` | string | required | Path of the webhook receiver. |
| `webhook_endpoint.method` | string | `POST` | HTTP method of the receiver (default POST). |
| `webhook_endpoint.body` | object | required | The webhook payload sent as the JSON body on every delivery. |
| `webhook_endpoint.signature_header` | string | required | Name of the header that carries the signature (e.g. 'X-Hub-Signature-256'). |
| `webhook_endpoint.signing_secret` | string | `""` | The shared secret the sender signs with, for the valid-signature positive control. A ${VAR} reference from the environment; never a literal in the repo. Empty: the positive control is skipped, and a rejected delivery is not verifiable (only an accepted forged one is judged). |
| `webhook_endpoint.signature_format` | string | `{signature}` | How the header value is built from the hex digest, e.g. 'sha256={signature}' (GitHub). '{signature}' is the lowercase hex HMAC-SHA256 of the raw body. |

<!-- [[[end]]] -->

## 13. Remediation

Verify an HMAC-SHA256 signature over the raw body on every delivery, in constant time; reject an absent or wrong
signature; add a timestamp-tolerance window and event-ID deduplication against replay (OWASP API10:2023, CWE-347,
OWASP Webhook Security Cheat Sheet).
