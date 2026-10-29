# ext.1.5.testssl TLS Stack Analysis

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-22) ·
> **Source of truth:**
> [`src/external_tests/ext_test_1_5_tls_analysis.py`](../../../../src/external_tests/ext_test_1_5_tls_analysis.py),
> [`src/connectors/testssl.py`](../../../../src/connectors/testssl.py) · **Verified:** 2026-10-22

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("ext.1.5.testssl", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `ext.1.5.testssl` |
| Name | TLS Stack Analysis (testssl.sh) |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P2 / BLACK_BOX |
| Effect | READ_ONLY |
| CWE | CWE-326 |
| Standards | `OWASP API8:2023`, `NIST SP 800-52r2`, `OWASP ASVS v5.0.0-12.1.1` |
| Tags | `transport-security`, `tls`, `cipher-suite`, `protocol-version` |
| Prerequisites | none |
| Needs | - |
| Parameters | none |
| Tool | `testssl` ([`external_tools.testssl`](../../../03-reference/01-configuration.md#external_tools)) |

<!-- [[[end]]] -->

**Tool:** testssl.sh (pinned by `install_tools.sh`). **Same guarantee:** test
[`1.5`](../../domain-1/1-5-credentials-over-an-insecure-channel.md) covers the HTTP layer (a plain-HTTP request
forced onto HTTPS, the HSTS header); this test scans the TLS handshake.

## 1. Guarantee

The TLS handshake that carries the credential is sound: only TLS 1.2/1.3 are offered, the cipher suites give forward
secrecy and authenticated encryption, the certificate chain is valid and trusted, and no known TLS vulnerability is
present. testssl.sh performs the scan; we point it at the gateway's HTTPS listener and judge its findings. We do not
reimplement the handshake (rule 11).

A PASS promises that testssl.sh reported no HIGH or CRITICAL weakness on the target. It promises nothing about the
HTTP redirect or HSTS (test `1.5`). OWASP API8:2023 (the hardening of the API stack, whose list names TLS); NIST SP 800-52 Rev.2; ASVS v5.0.0-12.1.1 (only the latest TLS
versions enabled).

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 1.5) |
|---|---|
| `tls_configuration` | "[audit] enabled protocols are only TLS 1.2/1.3"; "[audit] cipher suites give forward secrecy (ECDHE) and AEAD (GCM), no static RSA key exchange"; "[audit] the certificate is valid, from a trusted CA, CN/SAN match" |
| reported, not failed | the certificate's revocation status when it cannot be checked (no OCSP/CRL): the normal state of an internal private-CA gateway, not a cleartext-interception risk |
| left out | SCT / Certificate Transparency (RFC 6962): an issuance control outside testssl's default severity set |

## 3. Inputs

The HTTPS base URL (`target.endpoint_base_url()`), the tool's timeout and flags
(`external_tools.testssl.timeout_seconds`, `extra_flags`), and `target.tls.ca_bundle` (passed to testssl as
`--add-ca` so the configured authority is trusted too). No credential.

## 4. Preconditions and reference responses

testssl.sh must be installed (else SKIP). No reference responses: testssl connects to the target itself and its
findings are the evidence. A note states when certificate trust rests on the configured `ca_bundle`.

## 5. Probes

One testssl.sh scan of `host:port`, run as a subprocess through the connector. The reproducible command is shown in
the report for manual verification; its findings are read from the JSON output.

## 6. Oracle

| testssl.sh finding | Outcome / detail | Confidence |
|---|---|---|
| HIGH / CRITICAL (weak protocol, weak cipher, known CVE, untrusted chain) | `VIOLATION/TLS_WEAKNESS` (one finding per item) | FIRM: the tool observed it on the target; we did not re-derive it |
| HIGH / CRITICAL whose id is about revocation (no OCSP/CRL) | `NOT_VERIFIABLE/CERT_REVOCATION_NOT_CHECKABLE`, with a note | - |
| WARN / MEDIUM | a note, not a verdict | - |
| OK / INFO / LOW | ignored (not shown) | - |
| no HIGH/CRITICAL weakness | `ENFORCED/NO_TLS_WEAKNESS` | - |
| the scan could not connect / timed out | ERROR (the base class handles the tool error) | - |

The tool's own severity is kept in the finding text as information; the oracle reads the finding's id and severity
class, not the severity alone (rule 11).

## 7. Outcomes

SKIP when testssl.sh is not installed. Otherwise FAIL on any HIGH/CRITICAL weakness; PASS when there is none (a
**partial** PASS when the certificate's revocation could not be checked, which is NOT_VERIFIABLE with a note).

## 8. Findings

"TLS weakness (`<severity>`): `<id>`", with the tool's finding text and CVE when present; `evidence_ref` is the
tool's output artifact. The revocation case is a note, not a finding.

## 9. Effects on the target

`READ_ONLY`: a TLS handshake scan, no credential, no change to the target.

## 10. Per gateway

Independent of the adapter: testssl scans the HTTPS listener directly. The scan reaches whatever TLS endpoint
`base_url` names.

## 11. Configuration

No test parameter. The tool is configured under `external_tools.testssl` (`timeout_seconds`, `extra_flags`,
`expected_version`, `dev_mode`). testssl.sh is the single TLS analysis tool for this guarantee.

## 12. Validation

Runs of 2026-10-22:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, crAPI + Kong, Forgejo + APISIX | **PASS** partial | only TLS 1.2/1.3, ECDHE + AES-GCM ciphers: `tls_configuration` ENFORCED, no HIGH/CRITICAL; `cert_revocation` NOT_VERIFIABLE (the private CA has no OCSP/CRL), with a note |

**The weakness-present side (rule 9), by tool configuration, no gateway change.** With the specification kept on
HTTPS and `target.tls` set to `verify: false` (no `ca_bundle`), testssl scans without `--add-ca`: the private
certificate's chain is untrusted, testssl reports `cert_chain_of_trust` CRITICAL, and the test is **FAIL**, one
`VIOLATION/TLS_WEAKNESS`. The owner approved a weak-TLS gateway change for this side; the config-only path proved the
same oracle branch (HIGH/CRITICAL -> VIOLATION), so the gateway was left untouched. A weak protocol or cipher
specifically (as opposed to an untrusted chain) is a weakness the clean labs do not have; it would need a gateway
configured to offer TLS 1.0/1.1 or a weak cipher.

**What each branch has been seen doing** (rule 9). Proven: `ENFORCED/NO_TLS_WEAKNESS` and
`CERT_REVOCATION_NOT_CHECKABLE` (the three labs), `VIOLATION/TLS_WEAKNESS` (the no-ca case). Not exercised on a lab:
a weak-protocol/cipher violation, the connect/timeout ERROR.

## 13. Remediation

Disable every deprecated protocol (SSLv3, TLS 1.0/1.1) and weak cipher (RC4, 3DES, static RSA key exchange) in the
gateway's TLS configuration, keep only TLS 1.2/1.3 with ECDHE + AES-GCM, and serve a certificate from a CA the
clients trust (NIST SP 800-52 Rev.2, ASVS v5.0.0-12.1.1).

## 14. Limitations

- Certificate revocation that cannot be checked (no OCSP/CRL) is reported NOT_VERIFIABLE, not FAIL: on a public-CA
  certificate, enable OCSP so a compromised certificate can be revoked.
- The oracle rests on testssl.sh's severity class; a version whose output schema changed is warned about
  (`expected_version`).
- The HTTP redirect and HSTS are not judged here: see test `1.5`.

## 15. Sources

- OWASP API8:2023 Security Misconfiguration, whose list of weaknesses names "Transport Layer Security (TLS) is
  missing" and "appropriate security hardening is missing across any part of the API stack". API2:2023 was cited
  here until 2026-10-28: this test carries no credential and judges a TLS stack, and API2's own list says nothing
  about the handshake: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- NIST SP 800-52 Rev.2 (TLS configuration): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf
- OWASP ASVS v5.0.0-12.1.1 (only the latest TLS versions enabled, e.g. TLS 1.2/1.3): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md
- CWE-326 Inadequate Encryption Strength: https://cwe.mitre.org/data/definitions/326.html
- testssl.sh: https://testssl.sh/
