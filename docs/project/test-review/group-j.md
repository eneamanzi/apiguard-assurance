# Group J: guarantees 7.1, 7.2, 7.3, 7.4 (working file)

> **Audience:** the owner and me, during the review. Method: the six phases in
> [`test-review.md`](../test-review.md) (How we work).

| Phase | State |
|---|---|
| 1. Collection | done 2026-10-23 (below) |
| 2. Design | approved 2026-10-23 (decisions resolved at the end) |
| 3. Code | done 2026-10-26: 7.2 rewritten, 7.1/7.3/7.4 new (src/tests/domain_7/) |
| 4. Proof | done 2026-10-26: Forgejo 7.2 PASS (15 enf/58 nv), crAPI 7.2 INCONCLUSIVE (upstream), crAPI 7.1 FAIL; 7.3/7.4 SKIP |
| 5. Self-review | done 2026-10-26: fixed 7.2 false ENFORCED on 5xx (benign control + upstream rule) |
| 6. Documentation | done 2026-10-26: four pages in docs/05-tests/domain-7/, dev:gen + dev:check green |

**Outcome.** Group J complete (the last group). 7.2 proven agnostic on both Kong labs with the honest oracle; 7.1
VIOLATION proven on crAPI; 7.3/7.4 SKIP on the labs (no once-only operation / webhook receiver), their live branches
in Deferred follow-ups together with the out-of-band listener. Next: merge `test-review` into `main`.

**Owner's decisions (2026-10-23):** (1) **defer the out-of-band listener** -> 7.2 accepted payload is
NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED (not a false PASS); confirmed-SSRF and blind-webhook stay in Deferred
follow-ups. (2) **Build all four** (7.1, 7.2, 7.3, 7.4); 7.1/7.4 SKIP honestly where the labs declare no
sensitive/webhook endpoint. (3) Lab changes for rule 9 announced where needed.

Group J, the last, is business logic and sensitive flows: 7.1 automated abuse of sensitive flows, 7.2 SSRF, 7.3 race
conditions, 7.4 safe consumption of external services (webhooks). They share business flows, the out-of-band listener
and concurrency.

## Phase 1: collection (2026-10-23)

### The guarantees and what they need

| # | Guarantee | Needs to verify |
|---|---|---|
| 7.1 | sensitive flows resist automated abuse (CAPTCHA/anti-bot, OAT) | a declared sensitive endpoint; an anti-automation control (CAPTCHA token / aggressive 429) |
| 7.2 | SSRF is prevented (API7:2023, CWE-918, P0) | a URL-accepting endpoint; the SSRF payload catalogue; **an out-of-band listener to confirm the outbound call** |
| 7.3 | critical operations are idempotent / race-safe (CWE-362) | a critical operation; two users; concurrent requests (threads) |
| 7.4 | external services consumed safely (webhook HMAC, API10:2023) | the webhook endpoint and its signing secret; for blind cases, the listener |

### What exists and the central gap

- **7.2 on `main`:** sends the SSRF payload catalogue (`ssrf_payloads`: cloud metadata, loopback, RFC1918, encoding,
  protocols, redirect) to a configured `url_accepting_endpoint` and judges the **response**. Review defect (B6, Q-29):
  it judges acceptance (`200`/`201`) as the state, which does **not** prove the server made the outbound call -> a
  probable false PASS on crAPI challenge 11. Confirming the call needs an **out-of-band listener** (a URL the tool
  controls; a hit on it proves the SSRF). The lab configures crAPI's `contact_mechanic` as the URL-accepting endpoint.
- **7.1, 7.3, 7.4:** new. All are config-driven (a sensitive endpoint, a critical operation, a webhook endpoint +
  secret). The out-of-band listener (B6) is shared by 7.2 and 7.4 and is the heaviest piece of infrastructure in the
  whole review; it is already in the Deferred follow-ups.

### Boundaries (rule 10)

- **Infrastructure rate limiting** -> 4.1 (done); 7.1 is the business-flow anti-bot (CAPTCHA/OTP), a different control.
- **Login/registration enumeration and brute force** -> 1.7 (done); 7.1 is the broader automated-abuse of a
  high-value flow.
- **Request body validation** -> 3.1 (done); 7.4 is the signature over an inbound webhook.

## Phase 2: design (presented 2026-10-23)

### The out-of-band listener: the pivotal choice

A native listener (an HTTP server the tool starts, reachable by the target, with a unique token per payload) is the
only way to **confirm** an SSRF outbound call (7.2) or a blind webhook callback (7.4). On the labs it is fragile: the
target runs in Docker and must resolve a host address (`host.docker.internal` / the bridge IP), which varies. It is
the heaviest build in the review.

**My recommendation: defer the listener** (keep it in the Deferred follow-ups, shared with 7.4) and make 7.2 honest
**without** it: a payload that is rejected (`400`/timeout) is ENFORCED; a payload that is **accepted** is
`NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED` (not a false PASS, which is the current defect), stating the listener would
confirm it. The confirmed-SSRF VIOLATION then needs the listener.

### Compact design (without the listener)

- **7.2 SSRF (rewrite).** GREY_BOX (the URL-accepting endpoint often needs auth), effect CHANGES_DATA (it posts to a
  write endpoint). CWE-918. Sub-test `ssrf_payload_rejected`: each payload (metadata, loopback, RFC1918, encoding,
  non-HTTP protocol) sent to the configured `url_accepting_endpoint`; rejected (`400`, or a transport refusal) ->
  ENFORCED; **accepted (`2xx`) -> NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED** (honest: the outbound call is not confirmed
  from the response; the listener, deferred, would). One judgement per payload (fixes the single-aggregate-finding
  Q-50). SKIP without the configured endpoint.
- **7.3 Race Conditions (new).** GREY_BOX, two users, effect CHANGES_DATA. CWE-362. Sub-test
  `concurrent_requests_safe`: create a critical/owned object, fire N concurrent identical requests (native threads);
  the methodology's "one succeeds, the rest fail" is the safe case; all succeeding (a double effect) is the VIOLATION.
  Needs a configured critical operation; on the labs the owned-object order (test 2.2) is the candidate.
- **7.1 Sensitive-Flow Protection (new).** GREY_BOX, effect depends. CWE-799 (improper control of interaction
  frequency) / OAT. Sub-test `anti_automation_present`: a declared sensitive endpoint is sent a burst or a request
  without an anti-bot token; an anti-automation control (a `429`, a CAPTCHA-required `400`) present -> ENFORCED, none
  -> VIOLATION. Config-driven (the sensitive endpoint).
- **7.4 Webhook Verification (new).** BLACK_BOX, effect READ_ONLY-ish. CWE-345. Sub-test `signature_verified`: a
  configured webhook endpoint is sent a payload with an invalid/absent signature; rejected (`400`/`403`) -> ENFORCED,
  accepted (`2xx`, the forged webhook processed) -> VIOLATION. Config-driven (the webhook endpoint); the blind-callback
  and replay cases need the listener (deferred).

Much of 7.1/7.3/7.4 is config-driven: on the labs, crAPI gives SSRF (`contact_mechanic`) and the order object (race);
7.1/7.4 need a declared sensitive/webhook endpoint that the labs may not have, so those may be SKIP there (honest).

### Decisions for the owner (phase-2 go-ahead)

1. **The out-of-band listener: build now, or defer?** My recommendation: **defer** (it is the heaviest build and
   fragile on Docker), and fix 7.2 honestly (accepted payload -> NOT_VERIFIABLE, not a false PASS); the confirmed-SSRF
   and blind-webhook cases stay in the Deferred follow-ups. The alternative is to build a native listener now (a real
   sub-project). Your call.
2. **Scope now:** 7.2 (payload-rejection, honest) and 7.3 (native concurrency on the owned object) are doable on the
   labs; 7.1 and 7.4 are config-driven and may SKIP where the labs declare no sensitive/webhook endpoint. Do all four
   now (SKIP where the labs lack the input), or only 7.2 + 7.3 now and 7.1 + 7.4 when a target declares their inputs?
3. **Lab changes / config** for rule 9, announced where needed. Confirm.
