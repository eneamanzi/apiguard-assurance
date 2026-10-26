# 7.4 Webhook Signature Verification

> **Audience:** analysts, contributors · **Status:** new in the test review (branch `test-review`, 2026-10-26) ·
> **Source of truth:**
> [`src/tests/domain_7/test_7_4_webhook_verification.py`](../../../src/tests/domain_7/test_7_4_webhook_verification.py) ·
> **Verified:** 2026-10-26

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
| left out | **replay protection** (timestamp window, event-ID dedup) and the blind-callback case: both need the deferred out-of-band listener / a second delivery; constant-time comparison is not observable from outside |

## 3. Inputs

`webhook_endpoint` (no default): `path`, `method` (default `POST`), the `body` payload, the `signature_header` name,
an optional `signing_secret` (a `${VAR}` env reference, for the valid-signature positive control), and the
`signature_format` (default `{signature}`; e.g. `sha256={signature}` for GitHub). `{signature}` is the lowercase hex
HMAC-SHA256 of the raw body.

## 4. Preconditions and reference responses

**Positive control:** when `signing_secret` is set, a *validly* signed delivery is sent first. If even that is
rejected the endpoint refuses every delivery (down, or auth elsewhere), so a rejection proves nothing about signature
verification and both sub-tests are `NOT_VERIFIABLE/REJECTS_ALL`. Without the secret the control cannot run and a note
records that the enforcement is inferred, not confirmed.

## 5. Probes

Up to three deliveries of the same raw body: (optionally) validly signed, then unsigned, then wrongly signed. Effect
`CHANGES_DATA`: a processed webhook may change data (a rejected one does not); announce it on a shared target.

## 6. Oracle

**`absent_signature_rejected` / `invalid_signature_rejected`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the delivery is rejected (not `2xx`) | `ENFORCED/SIGNATURE_REQUIRED` | - |
| the unsigned delivery is accepted (`2xx`) | `VIOLATION/UNSIGNED_ACCEPTED` | CERTAIN |
| the wrongly signed delivery is accepted (`2xx`) | `VIOLATION/BAD_SIGNATURE_ACCEPTED` | CERTAIN |
| a valid signature was itself rejected | `NOT_VERIFIABLE/REJECTS_ALL` (both sub-tests) | - |
| no response | `NOT_VERIFIABLE/NO_RESPONSE` | - |

## 7. Outcomes

SKIP without `webhook_endpoint`. FAIL when a forged or unsigned delivery is accepted; PASS when both are rejected
(with a note if no positive control ran).

## 8. Findings

"Webhook accepted without a signature / with an invalid signature: `<method> <path>`", `evidence_ref` the accepted
delivery.

## 9. Effects on the target

`CHANGES_DATA`: deliveries to the receiver (rejected ones change nothing; an accepted forged one would be the
finding).

## 10. Per gateway

Independent of the adapter: the receiver is probed from outside.

## 11. Configuration

| Parameter | What it is | Default |
|---|---|---|
| `webhook_endpoint` | the receiver (`path`, `method`, `body`, `signature_header`, `signing_secret`, `signature_format`) | none (SKIP) |

## 12. Validation

Runs of 2026-10-26:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, crAPI + Kong, Forgejo + APISIX | **SKIP** | no webhook receiver declared (`webhook_endpoint` unset): honest SKIP |

Rule 9: the live branches (`VIOLATION/UNSIGNED_ACCEPTED`, `VIOLATION/BAD_SIGNATURE_ACCEPTED`,
`ENFORCED/SIGNATURE_REQUIRED`) are lab-unproven (the labs host no webhook receiver with a known signing scheme) and
listed in the Deferred follow-ups, together with replay protection and the blind-callback case, which need the
out-of-band listener.

## 13. Remediation

Verify an HMAC-SHA256 signature over the raw body on every delivery, in constant time; reject an absent or wrong
signature; add a timestamp-tolerance window and event-ID deduplication against replay (OWASP API10:2023, CWE-347,
OWASP Webhook Security Cheat Sheet).

## 14. Limitations

- Only the inbound-verification case is tested; replay protection, constant-time comparison, and blind callbacks are
  not (the last two are not observable from outside / need the listener).
- Only the `{signature}` placeholder is supported in `signature_format`; schemes that sign a timestamp+body tuple
  need an extension.

## 15. Sources

- OWASP API10:2023 Unsafe Consumption of APIs: https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/
- OWASP Webhook Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Webhook_Security_Cheat_Sheet.html
- CWE-347 Improper Verification of Cryptographic Signature: https://cwe.mitre.org/data/definitions/347.html
