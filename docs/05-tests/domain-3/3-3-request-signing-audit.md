# 3.3 Request Signing Audit

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_3/test_3_3_request_signing_audit.py`](../../../src/tests/domain_3/test_3_3_request_signing_audit.py)

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

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 3.3) |
|---|---|
| `algorithm_strong` | "the algorithm is SHA-256 or stronger; MD5/SHA-1 are non-conforming": by default only HMAC-MD5 is judged non-conforming (RFC 6151 advises against it in new designs), HMAC-SHA-1 only when the operator adds it, since RFC 6194 says "HMAC-SHA-1 remains secure" |
| `replay_protected` | "a timestamp window of at most 5 minutes, or a single-use nonce" |
| `content_signed` | "a request with a valid signature, body modified keeping the original signature" (the empirical case, read from the configuration): the signature must cover the body digest and the method and path, or a proxy changes them undetected |
| left out | the empirical tamper/replay test: meaningful only on a target that implements signing, which no lab does; not planned |

### 2.2 Preconditions and reference responses

`Need.GATEWAY` (the Admin API). No reference responses: the configuration read is the evidence.

### 2.3 Probes

None: a configuration audit. Every **enabled** policy is audited (not only the first).

## 3. Oracle

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

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("3.3", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 15 of 15 produced cases gave the declared outcome; 4 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `algorithm_strong/VIOLATION/SIGNATURE_OPTIONAL/FIRM` | forgejo-kong: hmac-auth given an anonymous consumer: an unsigned request passes as that consumer | OK |
| `algorithm_strong/VIOLATION/WEAK_ALGORITHM/FIRM` | forgejo-kong: hmac-auth allows hmac-sha1, and the run forbids hmac-sha1 | OK |
| `algorithm_strong/ENFORCED/STRONG_ALGORITHM` | forgejo-kong: the lab as built: hmac-sha256, -384, -512 only | OK |
| `algorithm_strong/NOT_VERIFIABLE/ALGORITHMS_NOT_STATED` | not producible (gateway): Kong's Admin API gives every field of the plugin with its default, and the APISIX adapter fills a field left out from the plugin's schema read from the running APISIX: the supported gateways always state it | - |
| `algorithm_strong/NOT_APPLICABLE/NO_SIGNING` | forgejo-apisix: hmac-auth removed from the only route that has it | OK |
| `algorithm_strong/NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | forgejo-kong: the run's gateway.admin.url points to a closed port | OK |
| `replay_protected/VIOLATION/REPLAY_UNBOUNDED/CERTAIN` | not producible (gateway): Kong requires clock_skew > 0, and APISIX 3.19 refuses 0 (its Admin API answered 400, 'expected 0 to be at least 1') | - |
| `replay_protected/VIOLATION/REPLAY_WINDOW_TOO_LARGE/CERTAIN` | forgejo-kong: hmac-auth with a 600 s clock skew, above the 300 s bound | OK |
| `replay_protected/VIOLATION/REPLAY_DATE_NOT_SIGNED/FIRM` | forgejo-kong: the lab as built: hmac-auth checks the clock skew on X-Date or Date and requires neither in the signature | OK |
| `replay_protected/ENFORCED/REPLAY_BOUNDED` | forgejo-apisix: the lab as built: APISIX checks Date, signed by default (signed_headers defaults to date) | OK |
| `replay_protected/NOT_VERIFIABLE/REPLAY_WINDOW_NOT_STATED` | not producible (gateway): Kong's Admin API gives every field of the plugin with its default, and the APISIX adapter fills a field left out from the plugin's schema read from the running APISIX: the supported gateways always state it | - |
| `replay_protected/NOT_APPLICABLE/NO_SIGNING` | forgejo-apisix: hmac-auth removed from the only route that has it | OK |
| `replay_protected/NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | forgejo-kong: the run's gateway.admin.url points to a closed port | OK |
| `content_signed/ENFORCED/CONTENT_SIGNED` | forgejo-kong: hmac-auth requires date, x-date, digest and request-line | OK |
| `content_signed/VIOLATION/BODY_NOT_SIGNED/FIRM` | forgejo-kong: the lab as built: the body is validated but digest is not required in the signature | OK |
| `content_signed/VIOLATION/TARGET_NOT_SIGNED/FIRM` | forgejo-kong: hmac-auth requires digest but not request-line | OK |
| `content_signed/NOT_VERIFIABLE/CONTENT_NOT_STATED` | not producible (gateway): Kong's Admin API gives every field of the plugin with its default, and the APISIX adapter fills a field left out from the plugin's schema read from the running APISIX: the supported gateways always state it | - |
| `content_signed/NOT_APPLICABLE/NO_SIGNING` | forgejo-apisix: hmac-auth removed from the only route that has it | OK |
| `content_signed/NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | forgejo-kong: the run's gateway.admin.url points to a closed port | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("3.3", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- Configuration audit only: the test reads the gateway's signing policy and never sends a crafted signed request, so
  it proves a mechanism is configured, not that the gateway rejects a tampered or replayed one. An empirical
  tamper/replay test is not planned: it would be meaningful only on a target that implements signing, and none of the
  three labs does.
- Reads only what the adapter's `signing_policies` exposes; a signing mechanism in the application (not the gateway)
  is not seen.
- `content_signed` reads what the gateway requires in the signature, not which headers a client signs: a client that
  signs more is not credited, and the empirical tampering request is not sent (first limitation).

## 6. Sources

- NIST SP 800-107 Rev.1 (HMAC algorithm strength and use): https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf
- RFC 6151 section 2.3 (HMAC-MD5: "The attacks on HMAC-MD5 do not seem to indicate a practical vulnerability when
  used as a message authentication code", but not to be included in a new protocol design):
  https://www.rfc-editor.org/rfc/rfc6151
- RFC 6194 sections 3.3 and 4 ("HMAC-SHA-1 remains secure"): https://www.rfc-editor.org/rfc/rfc6194
- OWASP ASVS v5.0.0, V4.1.5: "Verify that per-message digital signatures are
  used to provide additional assurance on top of transport protections for requests or transactions which are
  highly sensitive or which traverse a number of systems" (chapter V4 API and Web Service, section V4.1 Generic
  Web Service Security, level 3): https://github.com/OWASP/ASVS/blob/master/5.0/en/0x13-V4-API-and-Web-Service.md
- CWE-347 Improper Verification of Cryptographic Signature: https://cwe.mitre.org/data/definitions/347.html

## 7. Inputs

The gateway's signing policies (`signing_policies`, read through the adapter): per policy, `algorithms`,
`replay_window_seconds`, `date_signed`, `body_signed`, `target_signed`, `optional`. No request is sent.

## 8. Outcomes

SKIP when the gateway has no signing policies to read (not supported); INCONCLUSIVE, `CONCEPT_NOT_ACCESSIBLE` on
both sub-tests, when it has them but they cannot be read. NOT_APPLICABLE (PASS-neutral) when no policy is configured. FAIL on a
weak algorithm, an unbounded/too-large replay window, or a body or target the signature need not cover; PASS when
every enabled policy is strong, bounded and covers the content.

## 9. Findings

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

## 10. Effects on the target

`READ_ONLY`: reads the gateway Admin API.

## 11. Per gateway

Independent of the adapter: the oracle reads the neutral `signing_policies` concept and never names a gateway's own
plugin. Kong's `hmac-auth` maps to it; APISIX's equivalent likewise.

## 12. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("3.3", page=cog.inFile)) ]]] -->

Section [`tests.domain_3.test_3_3`](../../03-reference/01-configuration.md#testsdomain_3test_3_3) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `max_replay_window_seconds` | int ≥1 | `300` | The largest acceptable replay window (clock-skew tolerance) in seconds; above it a signed request can be replayed. Default 300 (5 minutes). |
| `forbidden_algorithms` | list | `hmac-md5`, `md5` | HMAC algorithms treated as weak (compared lowercased). Default md5: RFC 6151 advises against HMAC-MD5 in new designs; HMAC-SHA-1 is not weak (RFC 6194) unless added here. |

<!-- [[[end]]] -->

## 13. Remediation

If request signing is used, allow only HMAC-SHA-256 or stronger and bound replay with a short timestamp window
(<= 5 minutes, the methodology's bound) or a single-use nonce. Its absence is a gap to assess against the threat model
(trusted intermediary proxies on the path), not necessarily a failure.
