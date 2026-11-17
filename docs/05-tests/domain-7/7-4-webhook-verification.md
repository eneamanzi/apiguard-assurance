# 7.4 Webhook Signature Verification

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-26) ·
> **Source of truth:**
> [`src/tests/domain_7/test_7_4_webhook_verification.py`](../../../src/tests/domain_7/test_7_4_webhook_verification.py) ·
> **Verified:** 2026-11-16

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

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 7.4) |
|---|---|
| `absent_signature_rejected` | "a delivery with no signature must be rejected" |
| `invalid_signature_rejected` | "a delivery with a wrong signature must be rejected" |
| left out | **replay protection** (timestamp window, event-ID dedup): not judgeable from the answer, see Limitations; the **blind-callback** case: it needs an out-of-band listener the tool controls, which is not built and not planned (decided 2026-10-27); constant-time comparison is not observable from outside |

## 3. Inputs

`webhook_endpoint` (no default): `path`, `method` (default `POST`), the `body` payload, the `signature_header` name,
an optional `signing_secret` (a `${VAR}` env reference, for the valid-signature positive control), and the
`signature_format` (default `{signature}`; e.g. `sha256={signature}` for GitHub). `{signature}` is the lowercase hex
HMAC-SHA256 of the raw body.

## 4. Preconditions and reference responses

**Positive control:** when `signing_secret` is set, a *validly* signed delivery is sent first. A rejection of the
forged deliveries is evidence only when that valid one was accepted (`2xx`). If even the valid one is rejected, the
endpoint refuses every delivery (down, or auth elsewhere): both sub-tests are `NOT_VERIFIABLE/REJECTS_ALL`. Without
the secret, or when the valid delivery gets no usable answer (none, `5xx`, `429`), a rejection is
`NOT_VERIFIABLE/SIGNATURE_NOT_CONFIRMED`, and a note says how to confirm it: a wrong path (404) or a credential
required elsewhere (401) would be rejected the same way. An accepted forged delivery is a violation with or without
the control.

## 5. Probes

Up to three deliveries of the same raw body: (optionally) validly signed, then unsigned, then wrongly signed. Effect
`CHANGES_DATA`: a processed webhook may change data (a rejected one does not); announce it on a shared target.

## 6. Oracle

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

Until 2026-11-16 the validly signed delivery went first: a receiver that drops a repeated event (an event-ID cache, as the OWASP Webhook Security Cheat Sheet recommends) answered the forged ones as duplicates, a false PASS, or acknowledged them with `200`, a false FAIL; now it goes last, and only when a forged delivery was refused. A forged delivery accepted was CERTAIN, although a receiver may acknowledge at once and verify from a queue (the cheat sheet's advice): now FIRM. Any answer but a `2xx` counted as a refusal (a redirect included).

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("7.4", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 7. Outcomes

SKIP without `webhook_endpoint`. FAIL when a forged or unsigned delivery is accepted; PASS when both are rejected
(with a note if no positive control ran).

## 8. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("7.4")) ]]] -->

- "Webhook accepted without a signature: <method> <path>"
- "Webhook accepted with an invalid signature: <method> <path>"

<!-- [[[end]]] -->

`evidence_ref` the accepted delivery.

## 9. Effects on the target

`CHANGES_DATA`: deliveries to the receiver (rejected ones change nothing; an accepted forged one would be the
finding).

## 10. Per gateway

Independent of the adapter: the receiver is probed from outside.

## 11. Configuration

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

## 12. Validation

**2026-11-16, after the review**: a Forgejo + Kong route (`pre-function`, undone) accepting a delivery with a non-zero `X-Sig` and refusing the others with `401`: **PASS**, both forged deliveries refused, then the validly signed one accepted.


Runs of 2026-10-26:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, crAPI + Kong, Forgejo + APISIX | **SKIP** | no webhook receiver declared (`webhook_endpoint` unset): honest SKIP |

**Checked against a scratch receiver** (2026-11-04, after the correction of that day): a small
HTTP server outside the repository that accepts a delivery only with `X-Signature: sha256=<HMAC-SHA256 of the raw
body>`, plus a path that accepts anything.

| Case | Answers | Status |
|---|---|---|
| receiver, correct secret | valid 204, unsigned 401, wrongly signed 401 | **PASS**, `SIGNATURE_REQUIRED` twice |
| receiver, wrong secret | valid 401 | INCONCLUSIVE, `REJECTS_ALL` |
| receiver, no secret | 401, 401 | INCONCLUSIVE, `SIGNATURE_NOT_CONFIRMED` (PASS before the correction) |
| a wrong path, no secret | 404, 404 | INCONCLUSIVE, `SIGNATURE_NOT_CONFIRMED` (PASS before the correction) |
| the path that accepts anything, with or without the secret | 204 to every delivery | **FAIL**, `UNSIGNED_ACCEPTED` and `BAD_SIGNATURE_ACCEPTED` |
| Forgejo + Kong lab, `POST /api/v1/markdown`, no secret | 401, 401 (Forgejo requires a token there) | INCONCLUSIVE, `SIGNATURE_NOT_CONFIRMED` (PASS before the correction) |

The same check found a defect in the correction itself before it was kept (the control's answer was read inverted).

**This test has never run on a lab's own webhook receiver.** It needs the address of an incoming webhook receiver and, for its positive
control, the receiver's signing secret; none of the three lab applications has such a receiver (Forgejo sends
webhooks, it does not receive signed ones; crAPI has none), and building one would be new lab machinery, so none was
built (owner's decision, 2026-11-03). Its logic was read and corrected on that day (a `5xx`, a `429` or a dropped
connection no longer counts as "signature required"); its verdicts were observed only on the scratch receiver
above. Replay protection and the blind-callback case stay outside what this test covers, for the reasons in the
Limitations.

**What each branch has been seen doing** (rule 9). Proven on a lab: the SKIP (all three), `SIGNATURE_NOT_CONFIRMED`
(Forgejo + Kong, `POST /api/v1/markdown`). Seen on the scratch receiver only: `SIGNATURE_REQUIRED`, `REJECTS_ALL`,
`SIGNATURE_NOT_CONFIRMED`, `UNSIGNED_ACCEPTED`, `BAD_SIGNATURE_ACCEPTED`. On a lab on 2026-11-15 (Forgejo + Kong,
the run's `webhook_endpoint` set to `/review-webhook-receiver`, a temporary route there, undone with `git
checkout`): `UPSTREAM_UNAVAILABLE` (`503`), `SERVER_ERROR` (`500`), `RATE_LIMITED` (`429`), `NO_RESPONSE`
(sleeping 7 s, the run's `target.read_timeout: 5.0`), on both sub-tests. Every branch of this test has been seen.

## 13. Remediation

Verify an HMAC-SHA256 signature over the raw body on every delivery, in constant time; reject an absent or wrong
signature; add a timestamp-tolerance window and event-ID deduplication against replay (OWASP API10:2023, CWE-347,
OWASP Webhook Security Cheat Sheet).

## 14. Limitations

- Only the inbound-verification case is tested. Constant-time comparison is not observable from outside.
- **Replay protection is not judgeable from the answer.** The test could send the same signed delivery twice, but a
  `2xx` to the second proves nothing: a receiver that recognises the duplicate and ignores it (idempotent handling)
  answers `2xx` too. A delivery that is
  validly signed but old, which must be refused, can be built only with a scheme that signs a timestamp, which
  `signature_format` does not support (next item). So a receiver that verifies its HMAC correctly but accepts a
  replayed delivery still passes here. (Until 2026-11-05 this page said replay needs an out-of-band listener: that is
  true of the blind-callback case, an outbound call, not of an inbound replay.)
- The blind-callback case (the target calling a URL of ours) needs an out-of-band listener the tool controls, which
  is not built and not planned (decided 2026-10-27).
- Only the `{signature}` placeholder is supported in `signature_format`; schemes that sign a timestamp+body tuple
  need an extension.
- Only a hex HMAC-SHA256 over the raw body can be built (`signature_format`): a receiver expecting base64 (Shopify's scheme) refuses the valid delivery too, `REJECTS_ALL`.

## 15. Sources

- OWASP API10:2023 Unsafe Consumption of APIs: https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/
- OWASP Webhook Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Webhook_Security_Cheat_Sheet.html
- CWE-347 Improper Verification of Cryptographic Signature: https://cwe.mitre.org/data/definitions/347.html
