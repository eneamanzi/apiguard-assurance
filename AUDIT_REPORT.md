# APIGuard Assurance: full audit, 2026-11-03 (HEAD 04f41b9)

Read-only audit of the codebase and documentation. No repository file was changed. Lab requests were read-only
(GETs, `docker inspect`, displayed tool commands, a few `apiguard run` limited to one or two tests on scratch copies of
the lab configs); nothing was created on a lab. Ground truth: the three full runs of 2026-11-03 in `outputs/`.

Automatic checks: `hatch run dev:check` passes (ruff, mypy, bandit 5 low, vulture, import-linter 3/3 contracts,
169 config keys, 47 generated files up to date).

Detailed findings per area (each with location, evidence, failure scenario, suggested resolution):
`findings_D0.md`, `findings_D1.md`, `findings_D235.md`, `findings_D467.md`, `findings_CORE.md`, `findings_EXT.md`,
`findings_PIPE.md`, `findings_DOCS.md`, in the folder `audit-findings/` next to this file. IDs below refer to them.

## Status of the fixes (updated as they are made)

Legend: **Done** = fixed, checked on the labs (or on a scratch target when no lab has the case), page and CHANGELOG
updated, `dev:check` passing; To do = a clear fix not yet made; Owner decision = waits for the owner (one question at
a time, at the end of the clear fixes). Last update: 2026-11-04. Still to do after the list: correct the "load" and
"race" explanations of the crAPI 503s (root cause 4) in the docs, then reset crAPI and full runs on the three labs.

## Totals (after merging duplicates)

| Severity | Count |
|---|---|
| Critical | 3 |
| High | 25 |
| Medium | about 55 |
| Low / Info | about 70 |

## Root causes (the same defect seen from several tests)

1. **No catch-all for unexpected exceptions** (PIPE-1, D0-10, CORE-1). 16 native tests catch only
   `SecurityClientError`, and the engine has no guard around `test.execute`; v0.1.0 had one per test. Any other
   exception ends the run with exit 10 and no report. CORE-1 supplies a realistic trigger: a TCP reset escapes the
   client as a raw `httpx.ReadError` (only 6 httpx exceptions are mapped), with no evidence record.
2. **A non-2xx counted as enforcement without a reference that decides** (rule 1/3). D0-1, D0-2, D235-7, D235-8,
   D235-12, D467-3, D467-4, D467-17, D1-3, D1-7, D1-9, EXT-4. The pattern: a 401/404/422 is read as "refused" where
   nothing shows the control exists (no positive control for that method/role, or a calibration that cannot differ).
3. **Absence read as proof** (rule 1). D235-4 (mass assignment ENFORCED when no injected field is returned),
   D467-9 (6.1 CLEAN when every sample failed), EXT-1/EXT-4 (Schemathesis passes with nothing reached), D235-14 and
   CORE-3 (replay window "not stated" read as "unbounded", CERTAIN).
4. **7.2 trips the gateway's passive health check on crAPI** (D467-1, D0-9, EXT-2). Three 30 s cloud-metadata
   timeouts mark the workshop upstream unhealthy; the rest of 7.2, 0.1, 4.1, 4.4, 7.3 and Schemathesis then get
   Kong's 503. The pages blame load or races; Schemathesis turns the 503s into 17 FIRM findings.
5. **Claims attributed to standards that do not make them** (D1-2 NIST per-account limit, D1-4 ASVS 4.1.2 forbids
   API redirects that 1.5 rewards, D467-8 NIST 800-204A has no timeout values, D235-15 RFC 6151/6194 on HMAC,
   D467-19, D1-27, D235-21).
6. **Gateway access failures handled two ways** (CORE-6): SKIP (exit 0) in 3.3, 4.2, 5.1; NOT_VERIFIABLE (exit 3)
   in 0.2, 0.4, 4.3, 6.4. Design decision D7 documents only SKIP.

## Critical

| ID | Finding | Verdict | Status |
|---|---|---|---|
| EXT-1 | `ext.3.1.schemathesis` passes `--base-url` without the spec's base path; Schemathesis 3.x then drops `/api/v1`. On both Forgejo labs 723 requests all hit 404 outside the API and the test reports PASS complete. | CONFIRMED (source, offline repro, live run) | **Done** |
| EXT-2 | crAPI: 24 of 27 Schemathesis failures are Kong `503 failure to get a peer from the ring-balancer`, recorded as FIRM `INPUT_NOT_VALIDATED` (17 of 20 findings). Native tests classify the same answer NOT_VERIFIABLE. | CONFIRMED (artifact) | **Done** |
| D1-1 | When the credential is not in `Authorization` (apiKey header or query), the 1.2 JWT variants are stored unredacted; tampered keeps header+signature, alg-none keeps payload: together they rebuild the valid token. | CONFIRMED (code; labs not affected) | **Done** |

## High

| ID | Area | Finding | Status |
|---|---|---|---|
| PIPE-1 / CORE-1 | engine, client | Root cause 1 above. | **Done** |
| CORE-2 | evidence | 1.7 enumeration findings cite `1.7_006`, absent from `evidence.json` on all three labs (rule 6). Only unresolved ref in the three runs. | **Done** |
| CORE-3 / D235-14 | 3.3, APISIX | Unreadable APISIX schema answered READ without defaults; 3.3 maps a missing replay window to CERTAIN `REPLAY_UNBOUNDED` (also when `replay_unlimited` is false). | **Done** (CORE-3: schema unreadable -> not accessible; D235-14: an unstated window is not verifiable, only `replay_unlimited` is a violation) |
| D0-1 | 0.1 | On parametric paths probe and calibration are both random siblings: always "same as unknown", a handled method is counted refused (95 of 139 ENFORCED on each Forgejo lab). | **Done** |
| D0-2 | 0.1 | Undocumented versions: crAPI identity's catch-all 401 counted `VERSION_ABSENT` for v1/v3 (missing REFUSED_BEFORE_ROUTING guard). | **Done** |
| D0-3 | 0.4 | PASS on both Kong labs while the declared backends answer directly from the host (verified with GET); PASS rests only on derived localhost candidates. Kong reports hostnames, APISIX resolved IPs (CORE-8). | **Done** (no PASS on a derived refusal alone; owner: Kong's resolved IPs tried too, Kong labs now FAIL with evidence) |
| D1-2 | 1.7 | NIST SP 800-63B-4 limit is per account; the test probes a non-existent account and cites NIST as violated. | **Done** |
| D1-3 | 1.7 | Only 429 or slowdown counts as a limit; 403/423/changed 401 body ignored, FIRM `ATTEMPTS_NOT_LIMITED`. | **Done** |
| D1-4 | 1.5 | HTTP->HTTPS redirect judged ENFORCED and recommended; ASVS v5.0.0-4.1.2 forbids transparent redirects for API endpoints. All three labs PASS on a 301. | **Done** (owner: a redirect on an API path is `VIOLATION/TRANSPARENT_REDIRECT`, ASVS 4.1.2; labs now FAIL) |
| D1-5 | 1.1 | Malformed query-parameter credentials are sent as headers: sub-test ENFORCED without testing anything. | **Done** |
| D235-1 | 5.1 | CERTAIN "requests are not logged at the gateway"; all lab gateways write access logs. Oracle can only see log-shipping plugins. | **Done** |
| D235-2 | 5.1 | Decides on Kong/APISIX plugin-name fragments inside `src/tests`, user-visible text names both gateways (agnosticism, contrary to D7). | **Done** (owner: new `log_shipping` concept, lists in the adapters; 5.1 names no gateway) |
| D235-4 | 2.5 | Mass assignment ENFORCED when the read-back contains none of the injected fields (crAPI). | **Done** |
| D235-5 | 2.5 | Injection silently dropped when the create body is not a JSON object (`helpers/resources.py:282`). | **Done** |
| D235-6 | 2.5 | Sensitive-field check is a key substring, value ignored; crAPI finding is a masked card number returned to its owner. | **Done** |
| D235-7 | 2.2 (P0) | Modify/delete have no positive control; 422 from body validation (`{}` body) counted as ownership refusal. | **Done** |
| D235-8 | 2.1, 2.2 | A 401 for the probing role counted as enforcement without proving the credential works. | **Done** |
| D467-1 | 7.2 | Root cause 4 above; production risk of tripping a real breaker. | **Done** (owner: stop at the first 504/no answer; crAPI backend stays in service). Docs on the 503s: corrected after the final full runs |
| D467-2 | 7.2 (P0) | PASS while every cloud-metadata and private-IP URL was accepted (201); PASS rests on "Invalid url" syntax rejections. | **Done** (owner: INCONCLUSIVE when no cloud-metadata/private-IP URL is seen rejected; new `essential_sub_tests`) |
| D467-3 | 4.4 | Unauthenticated probe: a gateway-auth 401 (Kong key-auth runs before request-size-limiting) read as "body forwarded". | **Done** (owner: retry with user_a's credential after a 401/403; a forged credential tells who refused) |
| D467-4 | 7.4 | Without a signing secret, a 404 (typo) or gateway 401 gives PASS. | **Done** |
| PIPE-3 / D467-5 | 7.4, config_used | `signing_secret` not marked `SECRET_VALUE`: a literal secret is written in clear to `config_used.yaml`. | **Done** |
| EXT-3 | Schemathesis | No `--data-generation-method`: positive data only, `negative_data_rejection` never runs; docs say "valid and invalid". | **Done** |
| EXT-4 | Schemathesis | JUnit `<error>`/`<skipped>` ignored: a run where nothing executed is ENFORCED. | **Done** |

## Medium (one line each; details in the area files)

All to do unless marked done.

- **Tests 0.x:** **[D0-4 done]** D0-4 page describes an `APIGUARDPROBE` reference never in code; D0-5 static path calibrated on a parametric sibling; D0-6 SERVED identical to calibration -> CERTAIN with false text; D0-7 0.1 cleanup misses created objects and may DELETE a real path; D0-8 0.2 guard may sample a gateway plugin; D0-9 crAPI FAIL lost (root cause 4, owner decision 7); D0-11 catalogue promises a 0.4 backend list.
- **Tests 1.x:** D1-6 1.5 without `http_url` on a non-443 port gives CERTAIN false FAIL (reproduced); D1-7 transport failure ENFORCED (rule 4); D1-8 tampered JWT changes `sub`; D1-9 anchor accepted on 429/5xx; D1-10 1.2/1.4 cite no controls; D1-11 1.1 malformed values fully redacted, comment says otherwise; D1-12 1.3 "7 days" with no claims shown; D1-13 hard-coded token prefixes, duplicated; D1-14 1.6 empty-value clear hidden by redaction; D1-15 every cookie a "session cookie"; D1-16 user-visible lab names (1.2, 1.3, 1.4, 1.6, 1.5 param description).
- **Tests 2.x/3.3/5.1:** D235-3, D235-9, D235-10, D235-11, D235-12, D235-13, D235-15, D235-16 (crAPI orders left behind, page says deleted), **[D235-17 done]** D235-17.
- **Tests 4.x/6.x/7.x:** D467-6 APISIX default 503 rate-limit rejection not recognised; D467-7 4.1 stops on one 5xx; D467-8 NIST 800-204A thresholds; D467-9 6.1 transport failures skipped; D467-10 6.1 claims checks it does not make; D467-11 stack-trace substrings; D467-12 6.4 flags vault references; D467-13 lab paths in 7.1/7.2/7.3 examples (rendered into `config.example.yaml`); D467-14 7.3 no barrier/warm-up.
- **Core:** CORE-4 7.3 threads share the httpx cookie jar (cookie leakage, possible `RuntimeError` during iteration); **[CORE-5 done]** CORE-5 record URL drops query params (query credentials invisible); **[CORE-6 done]** CORE-6 gateway-inaccessible SKIP vs NOT_VERIFIABLE; CORE-7 Kong breaker reader keeps only the first plugin instance per name.
- **External:** EXT-5 to EXT-10 (testssl WARN tool problems shown as TLS notes with a local home path; exit code 1 misread; testssl can block on a prompt via inherited stdin, reproduced exit 245; ffuf `-maxtime` cut unnoticed; one finding text for all testssl families).
- **Pipeline:** PIPE-2 HTML report embedded JSON escapes only `</` (`<!--<script` can break the report); **[PIPE-4 done]** PIPE-4 all-SKIP run exits 0 (reproduced) against the exit-codes page.
- **Docs:** DOCS-1 fail-fast also on INCONCLUSIVE (6 places); DOCS-2 burst 300 vs 150; DOCS-3 wrong account roles (leaving out `user_b` silently SKIPs P0 2.2); DOCS-4 test counts 28/31; DOCS-5 `${VAR}` in comments; DOCS-6 nonexistent test 5.2; DOCS-7 client "not thread-safe"; **[DOCS-8 done]** DOCS-8 "only WHITE_BOX reads the gateway" false (5 BLACK_BOX tests read it); DOCS-9 report schema example stale; DOCS-10 `list-tests --json` table incomplete.

## Agnosticism summary

No logic in `src/engine.py`, `src/discovery/`, `src/report/`, `src/connectors/`, `src/external_tests/` branches on a
lab or gateway. Exceptions:
- ~~5.1 matches Kong/APISIX plugin names and names them in the finding (D235-2, High).~~ **Done** 2026-11-04.
- User-visible messages naming labs: 1.2/1.3 "Forgejo's API token is an opaque sha1 value", 1.4 "crAPI issues...",
  1.6 "Both lab applications...", 1.5 parameter description (D1-16).
- Parameter examples with lab paths in 7.1, 7.2 (`type: gitea`), 7.3 (`TRAC075`, `cart`), rendered into
  `config.example.yaml` (D467-13); `cli.py:733` help example; `engine.py:952` comment.
- Comments citing lab measurements (Low, acceptable by the brief).

## Thread-safety summary (7.3)

Sound: record-id counter and collector locked; results returned through `pool.map` and judged on the main thread;
evidence store and tally touched only on the main thread; no duplicate record ids in any evidence file.
Defects: shared cookie jar (CORE-4), raw `httpx` errors escape the worker's `except SecurityClientError` (CORE-1),
no barrier so "same instant" is not guaranteed (D467-14), duplicate log entry (CORE-12).

## Regressions

- PIPE-1: per-test catch-all removed during the block-6 rewrites (present in v0.1.0).
- D0-9 / D467-1: the validated crAPI FAIL of 0.1 and the 4.1/4.4/7.3 crAPI verdicts are no longer produced in a
  full run (run-order interaction with 7.2).
- No CLI command, option, config key or report field documented in the reference has disappeared (PIPE).

## Verified sound (highlights)

Status and coverage recomputed from counters match all three reports (rule 2); every evidence_ref and supporting_ref
resolves except CORE-2; 16 secret values scanned across 42 output files: 0 hits, no JWT or cookie in clear; selection,
DAG, needs, fail_fast mechanics, teardown and signal handling correct; report counters match rows; HTML autoescape;
no `shell=True`, temp files cleaned, no temp paths in displayed commands; testssl and Schemathesis displayed commands
run as shown; real FAILs proven by their evidence: 0.2 (all labs), 0.3, 0.4 APISIX, 0.1 route drift, 1.1 crAPI,
1.2 crAPI alg none, 2.1/2.2 crAPI, 4.4 Forgejo, 6.2 crAPI, 7.1 crAPI, ffuf Forgejo; all internal doc links resolve.

## Decisions for the owner

All open; asked one at a time after the clear fixes.

1. ~~CORE-6~~ decided 2026-11-04: not accessible -> INCONCLUSIVE everywhere, not supported -> SKIP; D7 aligned (**done**).
2. ~~CORE-8 / D0-3~~ decided 2026-11-04: yes, `TargetHealth.resolved`, tried by 0.4 (**done**).
3. ~~PIPE-4~~ decided 2026-11-04: an all-SKIP run exits 3 (**done**).
4. ~~D1-4~~ decided 2026-11-04: yes, `TRANSPARENT_REDIRECT` (**done**).
5. ~~DOCS-8~~ decided 2026-11-04: no, the strategy is not an access boundary; docs corrected (**done**).
6. EXT-17, D235-17: new config parameters. ~~D235-17~~ decided 2026-11-04: no key, 2.1's docs corrected (**done**). ~~EXT-17~~ decided 2026-11-04: `request_timeout_seconds` added (**done**).
7. ~~D467-1~~ decided 2026-11-04: 7.2 stops at the first payload without an answer or with 502/503/504 (**done**).
