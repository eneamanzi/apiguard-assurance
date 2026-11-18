# 3.3 Request Signing Audit

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_3/test_3_3_request_signing_audit.py`](../../../src/tests/domain_3/test_3_3_request_signing_audit.py) ·
> **Verified:** 2026-11-16

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("3.3", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `3.3` |
| Name | Request Signing Audit |
| Domain | 3 - Data Integrity |
| Priority / strategy | P3 / WHITE_BOX |
| Effect | READ_ONLY |
| CWE | CWE-347 |
| Standards | `NIST SP 800-107r1`, `RFC 6151, Section 2.3`, `OWASP ASVS v5.0.0-4.1.5`, `OWASP ASVS v5.0.0-11.4.1` |
| Tags | `integrity`, `request-signing` |
| Prerequisites | none |
| Needs | `GATEWAY` |
| Parameters | [`tests.domain_3.test_3_3`](../../03-reference/01-configuration.md#testsdomain_3test_3_3) |

<!-- [[[end]]] -->

**Same group:** test `3.1` / `ext.3.1.schemathesis` (data integrity).

## 1. Guarantee

Where the gateway signs requests (an HMAC beyond TLS), the signature uses a strong algorithm and bounds replay. A
PASS promises every enabled signing policy uses SHA-256 or stronger, a bounded replay window, and a signature that
must cover the body (its digest) and the method and path. The threat: a
trusted intermediary proxy tampers with a request, or replays a captured signed one. NIST SP 800-107. Request
signing is an advanced, optional control: its **absence is not a failure** (NOT_APPLICABLE with a note), only a weak
present configuration is.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 3.3) |
|---|---|
| `algorithm_strong` | "the algorithm is SHA-256 or stronger; MD5/SHA-1 are non-conforming": by default only HMAC-MD5 is judged non-conforming (RFC 6151 advises against it in new designs), HMAC-SHA-1 only when the operator adds it, since RFC 6194 says "HMAC-SHA-1 remains secure" (owner decision 2026-11-05) |
| `replay_protected` | "a timestamp window of at most 5 minutes, or a single-use nonce" |
| `content_signed` | "a request with a valid signature, body modified keeping the original signature" (the empirical case, read from the configuration): the signature must cover the body digest and the method and path, or a proxy changes them undetected (added 2026-11-16) |
| left out | the empirical tamper/replay test: meaningful only on a target that implements signing, which no lab does; not planned (2026-10-27) |

## 3. Inputs

The gateway's signing policies (`signing_policies`, read through the adapter): per policy, `algorithms`,
`replay_window_seconds`, `date_signed`, `body_signed`, `target_signed`, `optional`. No request is sent.

## 4. Preconditions and reference responses

`Need.GATEWAY` (the Admin API). No reference responses: the configuration read is the evidence.

## 5. Probes

None: a configuration audit. Every **enabled** policy is audited (not only the first).

## 6. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("3.3")) ]]] -->

**`algorithm_strong`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the policy lets a request without a valid signature through as an anonymous consumer | `VIOLATION/SIGNATURE_OPTIONAL` | FIRM |
| the policy allows an algorithm of `forbidden_algorithms` | `VIOLATION/WEAK_ALGORITHM` | FIRM |
| no allowed algorithm is forbidden | `ENFORCED/STRONG_ALGORITHM` | - |
| the gateway does not state the policy's algorithms | `NOT_VERIFIABLE/ALGORITHMS_NOT_STATED` | - |
| no enabled signing policy | `NOT_APPLICABLE/NO_SIGNING` | - |
| the gateway has the concept the test reads, and it could not be read (one rule for every test that reads one) | `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | - |

**`replay_protected`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the gateway states that the request's date is never checked | `VIOLATION/REPLAY_UNBOUNDED` | CERTAIN |
| a window above `max_replay_window_seconds` | `VIOLATION/REPLAY_WINDOW_TOO_LARGE` | CERTAIN |
| a bounded window, checked against a date the signature need not cover (a fresh unsigned date passes) | `VIOLATION/REPLAY_DATE_NOT_SIGNED` | FIRM |
| a window within `max_replay_window_seconds`, on a date the signature must cover | `ENFORCED/REPLAY_BOUNDED` | - |
| the gateway states no replay window | `NOT_VERIFIABLE/REPLAY_WINDOW_NOT_STATED` | - |
| no enabled signing policy | `NOT_APPLICABLE/NO_SIGNING` | - |
| the gateway has the concept the test reads, and it could not be read (one rule for every test that reads one) | `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | - |

**`content_signed`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the policy requires the body's digest and the request's method and path in the signature | `ENFORCED/CONTENT_SIGNED` | - |
| a changed body is not refused: no body check, or a digest the signature need not cover (FIRM: a client may sign it anyway, the gateway does not require it) | `VIOLATION/BODY_NOT_SIGNED` | FIRM |
| the body is covered, the method and path need not be | `VIOLATION/TARGET_NOT_SIGNED` | FIRM |
| the gateway does not state what the signature must cover | `NOT_VERIFIABLE/CONTENT_NOT_STATED` | - |
| no enabled signing policy | `NOT_APPLICABLE/NO_SIGNING` | - |
| the gateway has the concept the test reads, and it could not be read (one rule for every test that reads one) | `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | - |

<!-- [[[end]]] -->

Until 2026-11-16 a bounded window was `REPLAY_BOUNDED` even when the date it is checked against need not be signed: Kong checks the clock skew on `X-Date` or else `Date` and requires neither in the signature unless `enforce_headers` lists them (`kong/plugins/hmac-auth/access.lua` 3.9.3), so a captured request re-sent with a fresh date passes; APISIX checks `Date`, signed by default (`signed_headers` defaults to `["date"]`). And a policy with an anonymous fallback (Kong's `anonymous`, APISIX's `anonymous_consumer`), which lets an unsigned request through, read as enforced: now `SIGNATURE_OPTIONAL`. `WEAK_ALGORITHM` cannot happen with the defaults on the supported gateways (neither accepts md5). `content_signed` was added the same day: a signature that need not cover the body or the method and path leaves exactly the tampering of guarantee 3.3 undetected. Kong signs what `enforce_headers` requires (the body only with `validate_request_body` and `digest` required; the target with `request-line`), APISIX what `signed_headers` lists (with `validate_request_body`, and `@request-target`); both from the gateways' plugin sources (Kong `hmac-auth/access.lua` 3.9.3, APISIX `plugins/hmac-auth.lua`).

## 7. Outcomes

SKIP when the gateway has no signing policies to read (not supported); INCONCLUSIVE, `CONCEPT_NOT_ACCESSIBLE` on
both sub-tests, when it has them but they cannot be read (until 2026-11-04 a SKIP). NOT_APPLICABLE (PASS-neutral) when no policy is configured. FAIL on a
weak algorithm, an unbounded/too-large replay window, or a body or target the signature need not cover; PASS when
every enabled policy is strong, bounded and covers the content.

## 8. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("3.3")) ]]] -->

- "Request signature optional on '<name>'"
- "Weak signing algorithm on '<name>': <join>"
- "No replay window on signing policy '<name>'"
- "Replay window too large on '<name>': <window> s"
- "Replay window checked on an unsigned date on '<name>'"
- "Request body not covered by the signature on '<name>'"
- "Method and path not covered by the signature on '<name>'"

<!-- [[[end]]] -->

`evidence_ref` the signing-policies concept artifact.

## 9. Effects on the target

`READ_ONLY`: reads the gateway Admin API.

## 10. Per gateway

Independent of the adapter: the oracle reads the neutral `signing_policies` concept and never names a gateway's own
plugin. Kong's `hmac-auth` maps to it; APISIX's equivalent likewise.

## 11. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("3.3", page=cog.inFile)) ]]] -->

Section [`tests.domain_3.test_3_3`](../../03-reference/01-configuration.md#testsdomain_3test_3_3) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `max_replay_window_seconds` | int ≥1 | `300` | The largest acceptable replay window (clock-skew tolerance) in seconds; above it a signed request can be replayed. Default 300 (5 minutes). |
| `forbidden_algorithms` | list | `hmac-md5`, `md5` | HMAC algorithms treated as weak (compared lowercased). Default md5: RFC 6151 advises against HMAC-MD5 in new designs; HMAC-SHA-1 is not weak (RFC 6194) unless added here. |

<!-- [[[end]]] -->

## 12. Validation

**2026-11-16, after the review**: both Kong labs **FAIL**, `REPLAY_DATE_NOT_SIGNED` and `BODY_NOT_SIGNED`, both FIRM (their `hmac-auth` sets no `enforce_headers`; until that day PASS); Forgejo + APISIX **FAIL**, `BODY_NOT_SIGNED` (it validates the body, `validate_request_body: true`, but `digest` is not in `signed_headers`; `date` is signed by default, so `REPLAY_BOUNDED`). Two variants of Forgejo + Kong (2026-11-17, `enforce_headers` on `hmac-audit-dummy`, Kong recreated, the file restored and checked identical afterwards): `[date, x-date, digest]` gives **FAIL**, `TARGET_NOT_SIGNED` only (FIRM), with `REPLAY_BOUNDED`; `[date, x-date, digest, request-line]` gives **PASS**, `STRONG_ALGORITHM`, `REPLAY_BOUNDED`, `CONTENT_SIGNED`. `SIGNATURE_OPTIONAL` produced on 2026-11-17 by the validation campaign (`validation/`, variant `kong-hmac-anonymous`: a consumer added to Kong's file and named as `hmac-auth`'s `anonymous`): FAIL, `SIGNATURE_OPTIONAL` FIRM; the lab restored and checked identical.


Runs of 2026-10-23:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, crAPI + Kong, Forgejo + APISIX | **PASS** | the lab's signing policy uses hmac-sha256+ with a 300 s window (compliant) |
| Forgejo + Kong, with the change below | **FAIL**, 2 findings | the policy set to allow `hmac-sha1` and a 600 s window: `WEAK_ALGORITHM` + `REPLAY_WINDOW_TOO_LARGE` (measured when `hmac-sha1` was in the default list; since 2026-11-05 it is judged only when the operator adds it to `forbidden_algorithms`) |

**The case the labs lack, and how to undo it.** In `test-environments/forgejo-kong/kong/kong.yml`, on the
`hmac-audit-dummy` plugin, set `clock_skew: 600` and add `hmac-sha1` to `algorithms`, reload Kong (`docker compose
... up -d --force-recreate --wait kong`); undo with `git checkout` and the same command. The lab was checked back to
PASS. Rule 9: both sides proven; `NO_SIGNING` is the common real-world case (most APIs use no HMAC), documented but
not shown on the labs (all carry the compliant dummy policy).

**What each branch has been seen doing** (rule 9). Proven on a lab: `STRONG_ALGORITHM`, `REPLAY_BOUNDED` (all
three), `REPLAY_WINDOW_TOO_LARGE` (Forgejo + Kong with the change above), and `NO_SIGNING` (2026-11-15, Forgejo
+ APISIX, the `hmac-auth` plugin removed from `hmac-audit-route` in `apisix/setup.sh` and the setup run again, then
`git checkout` and the setup again: SKIP, "No request-signing policy configured"). Not produced:
`ALGORITHMS_NOT_STATED`, `REPLAY_WINDOW_NOT_STATED`, `CONTENT_NOT_STATED`. Kong's Admin API gives every field of the plugin with its
default, so it always states both; the APISIX adapter fills a field left out from the plugin's schema, read from the
running APISIX, so the two arise only when that schema cannot be read (`src/core/gateway/apisix.py`, "Default
values"), which no lab produces. Not reachable with the labs' gateways: `REPLAY_UNBOUNDED`.
Kong requires `clock_skew > 0`, and the lab's APISIX (3.19) refuses `0` as well: on 2026-11-15 its Admin API
answered `400`, "property \"clock_skew\" validation failed: expected 0 to be at least 1" (APISIX accepted `0`
before 3.13.0, `src/core/gateway/apisix.py`).

**A policy on a disabled route** (2026-11-15, Forgejo + APISIX, `hmac-audit-route` given `"status": 0`): judged
like any other, PASS. The test audits how signing is configured, not which traffic is signed (section 1), and the
policy is configured; `enabled` is the plugin's own switch (owner, 2026-11-15). `WEAK_ALGORITHM` was seen again with the current code
on 2026-11-14: the change above, and `forbidden_algorithms: [hmac-md5, md5, hmac-sha1]` in the run's configuration,
give **FAIL**, `WEAK_ALGORITHM` at FIRM and `REPLAY_WINDOW_TOO_LARGE` at CERTAIN; the lab was checked back to PASS.

## 13. Remediation

If request signing is used, allow only HMAC-SHA-256 or stronger and bound replay with a short timestamp window
(<= 5 minutes, the methodology's bound) or a single-use nonce. Its absence is a gap to assess against the threat model
(trusted intermediary proxies on the path), not necessarily a failure.

## 14. Limitations

- Configuration audit only: the test reads the gateway's signing policy and never sends a crafted signed request, so
  it proves a mechanism is configured, not that the gateway rejects a tampered or replayed one. An empirical
  tamper/replay test is not planned: it would be meaningful only on a target that implements signing, and none of the
  three labs does.
- Reads only what the adapter's `signing_policies` exposes; a signing mechanism in the application (not the gateway)
  is not seen.
- `content_signed` reads what the gateway requires in the signature, not which headers a client signs: a client that
  signs more is not credited, and the empirical tampering request is not sent (first limitation).

## 15. Sources

- NIST SP 800-107 Rev.1 (HMAC algorithm strength and use): https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf
- RFC 6151 section 2.3 (HMAC-MD5: "The attacks on HMAC-MD5 do not seem to indicate a practical vulnerability when
  used as a message authentication code", but not to be included in a new protocol design):
  https://www.rfc-editor.org/rfc/rfc6151
- RFC 6194 sections 3.3 and 4 ("HMAC-SHA-1 remains secure"): https://www.rfc-editor.org/rfc/rfc6194
- OWASP ASVS v5.0.0, V4.1.5 (verified on source 2026-10-27): "Verify that per-message digital signatures are
  used to provide additional assurance on top of transport protections for requests or transactions which are
  highly sensitive or which traverse a number of systems" (chapter V4 API and Web Service, section V4.1 Generic
  Web Service Security, level 3): https://github.com/OWASP/ASVS/blob/master/5.0/en/0x13-V4-API-and-Web-Service.md
- CWE-347 Improper Verification of Cryptographic Signature: https://cwe.mitre.org/data/definitions/347.html
