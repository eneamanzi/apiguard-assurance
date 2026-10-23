# Group G: guarantees 4.1, 4.2, 4.3, 4.4 (working file)

> **Audience:** the owner and me, during the review. Method: the six phases in
> [`test-review.md`](../test-review.md) (How we work).

| Phase | State |
|---|---|
| 1. Collection | done 2026-10-23 (below) |
| 2. Design | done 2026-10-23; owner decisions below |
| 3. Code | done 2026-10-23 |
| 4. Proof | done 2026-10-23 (three labs + an announced Kong plugin change for the enforced side) |
| 5. Self-review | done 2026-10-23 (4.1 evidence fix, below) |
| 6. Documentation | done 2026-10-23 |

### Decided (owner, 2026-10-23)

1. **4.1 native burst** (no vegeta), the limit derived from the gateway config where readable.
2. **4.4 shape:** empirical `413` on an oversized body + the gateway's size-limit config; CWE-400.
3. **Lab plugin change announced** to show the enforced side of 4.1/4.4.

### Results and review (2026-10-23)

| Lab | 4.1 | 4.2 | 4.3 | 4.4 |
|---|---|---|---|---|
| Forgejo + Kong, crAPI + Kong, Forgejo + APISIX | **FAIL** (no rate limit) | **PASS** | **PASS** (passive health check = Kong's breaker) | **FAIL** (no size limit) |
| Forgejo + Kong, with the plugins | 4.1 **PASS** (429 at the 6th, spoof resisted); 4.4 **PASS** (413 on 2 MB) | - | - | - |

4.1 and 4.4 FAIL on the default labs is a real gap (no rate/size plugin configured). The enforced side was proven by
adding a `rate-limiting` (5/min) and a `request-size-limiting` (1 MB) plugin to forgejo-kong's Kong, running, then
reverting (`git checkout`) and verifying the labs back to FAIL. New tests 4.1, 4.3, 4.4 on the new base; 4.2 is the
pilot, unchanged. `4.3` reuses the `circuit_breakers` and `health_checks` concepts; `4.1`/`4.4` read the gateway's
configured limit through `config_values` (optional `Need.GATEWAY`) and fall back to a parameter.

**Self-review fix:** 4.1's `NO_RATE_LIMIT` finding had no evidence (the 150-request burst was not logged). Fixed:
the burst's last request is kept and the finding points to it.

ASVS verified on source (v5.0.0): 2.4.1 (anti-automation, 4.1/4.4), 16.5.2 (operate when a resource fails, 4.3).

Group G is resource-consumption limits enforced by the gateway: 4.1 rate limiting, 4.2 timeouts, 4.3 circuit
breaker, 4.4 size limits (new). They share the gateway adapter's concepts (`src/core/gateway/`) and the config-audit
pattern of the 4.2 pilot.

## Phase 1: collection (2026-10-23)

### The guarantees (methodology, read on `04-guarantees.md`)

| # | Guarantee | Question | References (to verify on source) |
|---|---|---|---|
| 4.1 | rate limiting prevents abuse | does the gateway answer 429 past the limit, and resist X-Forwarded-For spoofing? | API4:2023, ASVS v5.0.0-2.4.1, NIST 800-204 §4.5 |
| 4.2 | timeouts prevent resource lock | are the gateway's backend timeouts set and bounded? | API4:2023, CWE-400, NIST 800-204A §4.3, ASVS v5.0.0-16.5.2 |
| 4.3 | circuit breaker / graceful degradation | does the gateway have a circuit breaker, or a passive health check as its equivalent? | API4:2023, ASVS v5.0.0-16.5.2, NIST 800-204 §4.5.1 |
| 4.4 | request/response size limits (new) | does the gateway reject an oversized body (413)? | API4:2023, CWE-400 (methodology: to decide) |

### What the gateway adapter exposes (`src/core/gateway/base.py`)

Concepts readable through `target.gateway`: `backend_timeouts`, `circuit_breakers`, `health_checks`,
`signing_policies`, `routes`, `config_values`, `target_health`. **No rate-limit or size-limit concept yet.** 4.1 and
4.4 are empirical (send a burst / an oversized body and read the answer); the gateway's configured limit can be read
through `config_values` where the adapter exposes it.

### State of each test

- **4.2 (timeouts): done.** The pilot, on the branch, with its page: reads `backend_timeouts`, a finding per
  timeout above its bound, CWE-400, WHITE_BOX, `Need.GATEWAY`, READ_ONLY. It is the template for 4.3. Its standards
  are to be verified on source in phase 6.
- **4.3 (circuit breaker):** on `main`, reads `circuit_breakers` and `health_checks`. Kong has no circuit-breaker
  plugin, so a passive health check (`healthchecks.passive`) is its equivalent (a compensating control). Rebuilt on
  the new base, following 4.2.
- **4.1 (rate limiting):** on `main`, empirical: sends `max_requests` and looks for a 429, plus an
  X-Forwarded-For spoofing check. Defects (review): the budget is a fixed `max_requests`, not derived from the
  configured limit; no `evidence_ref`; it exhausts the rate-limit budget of later tests (so it is `STRESSES_TARGET`
  and runs last). No vegeta connector exists.
- **4.4 (size limits): new.** No test, no gateway concept. Empirical: send an oversized body, expect `413 Payload
  Too Large`; read the gateway's size-limit config where available.

## Phase 2: design (presented 2026-10-23)

### The boundary (rule 10)

| Question | Test |
|---|---|
| is a flood of requests stopped (429), and is per-IP limiting spoof-resistant? | **4.1** |
| are the backend timeouts set and bounded? | **4.2** (done) |
| is there a circuit breaker (or a passive health check as its equivalent)? | **4.3** |
| is an oversized request body rejected (413)? | **4.4** |
| is a slow/abusive business flow stopped? (application logic, not infra) | 7.1 (group J) |

4.1 is about infrastructure availability (a flood), 7.1 about a business flow's logic (rule 10, the methodology's own
split). 4.2/4.3/4.4 are the other resource controls.

### Compact design

**4.1 Rate Limiting.** BLACK_BOX (a flood needs no credential; the per-user check uses user_a + user_b, GREY_BOX
when present), effect `STRESSES_TARGET` (runs last). Sub-tests: `limit_enforced` (send a burst to a documented
endpoint until 429, or to the configured limit + 1 when the gateway exposes it; 429 within the budget -> ENFORCED,
none -> VIOLATION/NO_RATE_LIMIT), `ip_spoofing_resisted` (the same burst with a random `X-Forwarded-For` per request;
a 429 still arrives -> ENFORCED, the burst never 429s while the plain burst did -> VIOLATION/IP_SPOOF_BYPASS). The
budget is derived from the gateway's rate-limit plugin config where readable (an improvement over the fixed
`max_requests`), else a configured cap. Confidence CERTAIN (the 429 is observed).

**4.2 Timeouts.** Done (pilot). Included in the group's proof; standards verified on source.

**4.3 Circuit Breaker.** WHITE_BOX, `Need.GATEWAY`, READ_ONLY, CWE-400 (or ASVS V16.5.2). Sub-test
`degradation_configured`: a circuit-breaker concept present -> ENFORCED; else a passive health check present (Kong's
equivalent) -> ENFORCED with a note (a compensating control); neither -> VIOLATION/NO_CIRCUIT_BREAKER. Reads the
gateway concepts; a non-readable concept -> SKIP (`_skip_for_concept`), as 4.2.

**4.4 Size Limits (new).** BLACK_BOX, effect `STRESSES_TARGET` (an oversized body), CWE-400. Sub-test
`oversized_body_rejected`: send a documented write endpoint a body above a threshold; `413` (or a refusal before the
body is processed) -> ENFORCED; a `2xx`/processing -> VIOLATION/NO_SIZE_LIMIT. Reads the gateway's size-limit config
where available. A new guarantee: its shape is the owner's to confirm.

### The three situations (rule 9)

- **Absent (enforced):** the labs' gateways set timeouts (4.2), Kong passive health checks (4.3). Rate limit (4.1)
  and size limit (4.4): to see on the labs, a Kong/APISIX plugin is configured (documented, reversible) or read if
  already present.
- **Present:** a gateway with no rate limit / no size limit / no breaker (a lab config without the plugin, or crAPI
  where a control is missing).
- **Not verifiable:** a gateway whose admin plane is not reachable (SKIP), a burst that only gets 503 (NOT_VERIFIABLE).

### Decisions for the owner (phase-2 go-ahead)

1. **4.1: native burst, or connect vegeta?** The methodology says HYBRID vegeta. A native burst (httpx) finds the
   429 boundary and runs the spoofing check without a new tool; vegeta adds precise requests-per-second pacing, which
   matters only for a limit expressed per second. My recommendation: **native burst now**, deriving the limit from
   the gateway config where readable, and defer vegeta (a new install that buys little here). Your call.
2. **4.4 (new guarantee) shape:** I propose an empirical `413` check on an oversized body plus a read of the
   gateway's size-limit config, CWE-400. Confirm the guarantee, since it is new (the methodology left it "to decide").
3. **New parameters** 4.1 (a burst cap / the endpoint) and 4.4 (the size threshold): new config parameters, flagged
   per the rule; I will keep them minimal and derive from the gateway where possible.
4. **A lab plugin change** to show the rate-limit / size-limit present-and-absent sides (rule 9): a documented,
   reversible Kong/APISIX plugin add, announced before I touch the lab. Confirm you want it, or prefer config-only.
