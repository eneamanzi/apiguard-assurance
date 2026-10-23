# 3.3 Request Signing Audit

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (branch `test-review`, 2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_3/test_3_3_request_signing_audit.py`](../../../src/tests/domain_3/test_3_3_request_signing_audit.py) ·
> **Verified:** 2026-10-23

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("3.3", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `3.3` |
| Name | Request Signing Audit |
| Domain | 3 - Data Integrity |
| Priority / strategy | P3 / WHITE_BOX |
| Effect | READ_ONLY |
| CWE | CWE-347 |
| Standards | `NIST SP 800-107` |
| Tags | `integrity`, `request-signing` |
| Prerequisites | none |
| Needs | `GATEWAY` |
| Parameters | [`tests.domain_3.test_3_3`](../../03-reference/01-configuration.md#testsdomain_3test_3_3) |

<!-- [[[end]]] -->

**Same group:** test `3.1` / `ext.3.1.schemathesis` (data integrity).

## 1. Guarantee

Where the gateway signs requests (an HMAC beyond TLS), the signature uses a strong algorithm and bounds replay. A
PASS promises every enabled signing policy uses SHA-256 or stronger and a bounded replay window. The threat: a
trusted intermediary proxy tampers with a request, or replays a captured signed one. NIST SP 800-107. Request
signing is an advanced, optional control: its **absence is not a failure** (NOT_APPLICABLE with a note), only a weak
present configuration is.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 3.3) |
|---|---|
| `algorithm_strong` | "the algorithm is SHA-256 or stronger; MD5/SHA-1 are non-conforming" |
| `replay_protected` | "a timestamp window of at most 5 minutes, or a single-use nonce" |
| left out (deferred) | the empirical tamper/replay test (only if a signing mechanism is implemented and a request can be crafted) |

## 3. Inputs

The gateway's signing policies (`signing_policies`, read through the adapter): per policy, `algorithms`,
`replay_window_seconds`. No request is sent.

## 4. Preconditions and reference responses

`Need.GATEWAY` (the Admin API). No reference responses: the configuration read is the evidence.

## 5. Probes

None: a configuration audit. Every **enabled** policy is audited (not only the first).

## 6. Oracle

**`algorithm_strong`** (per enabled policy)

| Case | Outcome / detail | Confidence |
|---|---|---|
| no forbidden algorithm (hmac-sha1, hmac-md5) | `ENFORCED/STRONG_ALGORITHM` | - |
| a forbidden algorithm is allowed | `VIOLATION/WEAK_ALGORITHM` | CERTAIN |
| the policy states no algorithms | `NOT_VERIFIABLE/ALGORITHMS_NOT_STATED` | - |

**`replay_protected`** (per enabled policy)

| Case | Outcome / detail | Confidence |
|---|---|---|
| a window within the maximum | `ENFORCED/REPLAY_BOUNDED` | - |
| no window stated | `VIOLATION/REPLAY_UNBOUNDED` | CERTAIN |
| a window above the maximum | `VIOLATION/REPLAY_WINDOW_TOO_LARGE` | CERTAIN |

No enabled policy -> both sub-tests `NOT_APPLICABLE/NO_SIGNING`, with a note (an advanced control absent, a gap to
assess against the threat model, not a failure).

## 7. Outcomes

SKIP when the signing policies cannot be read. NOT_APPLICABLE (PASS-neutral) when no policy is configured. FAIL on a
weak algorithm or an unbounded/too-large replay window; PASS when every enabled policy is strong and bounded.

## 8. Findings

"Weak signing algorithm on '`<policy>`': ...", "No replay window on signing policy '`<policy>`'", "Replay window too
large on '`<policy>`': `<n>` s", each pointing to the signing-policies concept artifact.

## 9. Effects on the target

`READ_ONLY`: reads the gateway Admin API.

## 10. Per gateway

Independent of the adapter: the oracle reads the neutral `signing_policies` concept and never names a gateway's own
plugin. Kong's `hmac-auth` maps to it; APISIX's equivalent likewise.

## 11. Configuration

| Parameter | What it is |
|---|---|
| `max_replay_window_seconds` | the largest acceptable replay window (default 300) |
| `forbidden_algorithms` | the HMAC algorithms treated as weak (default sha1/md5) |

## 12. Validation

Runs of 2026-10-23:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, crAPI + Kong, Forgejo + APISIX | **PASS** | the lab's signing policy uses hmac-sha256+ with a 300 s window (compliant) |
| Forgejo + Kong, with the change below | **FAIL**, 2 findings | the policy set to allow `hmac-sha1` and a 600 s window: `WEAK_ALGORITHM` + `REPLAY_WINDOW_TOO_LARGE` |

**The case the labs lack, and how to undo it.** In `test-environments/forgejo-kong/kong/kong.yml`, on the
`hmac-audit-dummy` plugin, set `clock_skew: 600` and add `hmac-sha1` to `algorithms`, reload Kong (`docker compose
... up -d --force-recreate --wait kong`); undo with `git checkout` and the same command. The lab was checked back to
PASS. Rule 9: both sides proven; `NO_SIGNING` is the common real-world case (most APIs use no HMAC), documented but
not shown on the labs (all carry the compliant dummy policy).

## 13. Remediation

If request signing is used, allow only HMAC-SHA-256 or stronger and bound replay with a short timestamp window
(<= 5 minutes) or a single-use nonce (NIST SP 800-107). Its absence is a gap to assess against the threat model
(trusted intermediary proxies on the path), not necessarily a failure.

## 14. Limitations

- Configuration audit only: the empirical tamper/replay test (a crafted signed request) is a deferred follow-up,
  meaningful only where a signing mechanism is implemented.
- Reads only what the adapter's `signing_policies` exposes; a signing mechanism in the application (not the gateway)
  is not seen.

## 15. Sources

- NIST SP 800-107 Rev.1 (HMAC algorithm strength and use): https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf
- OWASP ASVS v5.0.0-4.1.5 (to verify on source; WebFetch was rate-limited 2026-10-23)
- CWE-347 Improper Verification of Cryptographic Signature: https://cwe.mitre.org/data/definitions/347.html
