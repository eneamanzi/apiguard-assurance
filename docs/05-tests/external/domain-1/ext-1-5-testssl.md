# ext.1.5.testssl TLS Stack Analysis

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/external_tests/ext_test_1_5_tls_analysis.py`](../../../../src/external_tests/ext_test_1_5_tls_analysis.py), [`src/connectors/testssl.py`](../../../../src/connectors/testssl.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("ext.1.5.testssl", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `ext.1.5.testssl` |
| Name | TLS Stack Analysis (testssl.sh) |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P2 / BLACK_BOX |
| Effect | READ_ONLY |
| CWE | CWE-326 |
| Standards | `OWASP API8:2023`, `NIST SP 800-52r2`, `OWASP ASVS v5.0.0-12.1.1`, `OWASP ASVS v5.0.0-12.1.2`, `OWASP ASVS v5.0.0-12.2.2`, `RFC 8996` |
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

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 1.5) |
|---|---|
| `tls_configuration` | "[audit] enabled protocols are only TLS 1.2/1.3"; "[audit] cipher suites give forward secrecy (ECDHE) and AEAD (GCM), no static RSA key exchange"; "[audit] the certificate is valid, from a trusted CA, CN/SAN match" |
| reported, not failed | the certificate's revocation status when it cannot be checked (no OCSP/CRL): the normal state of an internal private-CA gateway, not a cleartext-interception risk |
| left out | SCT / Certificate Transparency (RFC 6962): an issuance control outside testssl's default severity set |

### 2.2 Preconditions and reference responses

testssl.sh must be installed (else SKIP). No reference responses: testssl connects to the target itself and its
findings are the evidence. A note states when certificate trust rests on the configured `ca_bundle`.

### 2.3 Probes

One testssl.sh scan of `host:port`, run as a subprocess through the connector, with `--warnings batch` and no
terminal input, so that it never waits for a keypress (on a plain-HTTP target it asked "Really proceed?" and waited
until the timeout). The reproducible command is shown in the report for manual verification;
its findings are read from the JSON output. Its exit code is the number of errors or ambiguous results it met
(testssl.sh's manual, "EXIT STATUS"): the scan completed and its findings are judged, the count goes in a note;
only 242 and above (its own failures: connectivity, DNS, OpenSSL) are an error. 
## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("ext.1.5.testssl")) ]]] -->

| Case | Outcome / detail | Confidence |
|---|---|---|
| testssl.sh finds SSLv2, SSLv3, TLS 1.0 or TLS 1.1 offered (a handshake succeeded) | `VIOLATION/DEPRECATED_PROTOCOL` | CERTAIN |
| testssl.sh rates a finding HIGH or CRITICAL (not about revocation) | `VIOLATION/TLS_WEAKNESS` | FIRM |
| a HIGH or CRITICAL finding about revocation (no OCSP or CRL) | `NOT_VERIFIABLE/CERT_REVOCATION_NOT_CHECKABLE` | - |
| no weakness, and a FATAL entry says the scan did not finish | `NOT_VERIFIABLE/SCAN_INCOMPLETE` | - |
| no weakness and no deprecated protocol in a finished scan | `ENFORCED/NO_TLS_WEAKNESS` | - |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("ext.1.5.testssl", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../../experiments/README.md), campaign at commit `fc60b6f`. 4 of 4 produced cases gave the declared outcome; 1 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `tls_configuration/VIOLATION/DEPRECATED_PROTOCOL/CERTAIN` | forgejo-kong: Kong recreated with KONG_SSL_PROTOCOLS=TLSv1 TLSv1.1 TLSv1.2 TLSv1.3 and KONG_SSL_CIPHER_SUITE=old: testssl.sh finds TLS1 and TLS1_1 offered | OK |
| `tls_configuration/VIOLATION/TLS_WEAKNESS/FIRM` | forgejo-kong: target.tls set to verify: false with no ca_bundle, so testssl.sh runs without --add-ca and rates the private chain cert_chain_of_trust CRITICAL | OK |
| `tls_configuration/NOT_VERIFIABLE/CERT_REVOCATION_NOT_CHECKABLE` | forgejo-kong: the lab as built: the labs' private CA offers no OCSP or CRL, which testssl.sh rates HIGH | OK |
| `tls_configuration/NOT_VERIFIABLE/SCAN_INCOMPLETE` | not producible (environment): the page: 'Not produced: `SCAN_INCOMPLETE` (a FATAL entry of testssl.sh with no weakness found)'. In testssl.sh 3.x a FATAL entry without exiting comes only from ip_fatal (a host name that resolves to several addresses, one of which refuses the connection); every other FATAL exits with 242 or above, which the connector turns into ERROR. The labs' base URL is localhost, which resolves to 127.0.0.1 only, and any other name fails the certificate's names (localhost, 127.0.0.1, kong, apisix), which testssl.sh rates as a weakness | - |
| `tls_configuration/ENFORCED/NO_TLS_WEAKNESS` | forgejo-kong: the lab as built: only TLS 1.2/1.3 with ECDHE + AES-GCM, no HIGH or CRITICAL finding other than revocation | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("ext.1.5.testssl", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- Certificate revocation that cannot be checked (no OCSP/CRL) is reported NOT_VERIFIABLE, not FAIL: on a public-CA
  certificate, enable OCSP so a compromised certificate can be revoked.
- The oracle rests on testssl.sh's severity class; a version whose output schema changed is warned about
  (`expected_version`).
- The HTTP redirect and HSTS are not judged here: see test `1.5`.
- testssl.sh's summary of the HTTP security headers (`security_headers`) is not shown: those headers are test
  `6.2`'s question (rule 10). 
## 6. Sources

- OWASP API8:2023 Security Misconfiguration, whose list of weaknesses names "Transport Layer Security (TLS) is
  missing" and "appropriate security hardening is missing across any part of the API stack". API2:2023 is not
  cited: this test carries no credential and judges a TLS stack, and API2's own list says nothing
  about the handshake: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- NIST SP 800-52 Rev.2 (TLS configuration): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf
- OWASP ASVS v5.0.0-12.1.1 (only the latest TLS versions enabled, e.g. TLS 1.2/1.3): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md
- CWE-326 Inadequate Encryption Strength: https://cwe.mitre.org/data/definitions/326.html
- testssl.sh: https://testssl.sh/

## 7. Inputs

The HTTPS base URL (`target.endpoint_base_url()`), the tool's timeout and flags
(`external_tools.testssl.timeout_seconds`, `extra_flags`), and `target.tls.ca_bundle` (passed to testssl as
`--add-ca` so the configured authority is trusted too). No credential.

## 8. Outcomes

SKIP when testssl.sh is not installed. Otherwise FAIL on any HIGH/CRITICAL weakness; PASS when there is none (a
**partial** PASS when the certificate's revocation could not be checked, which is NOT_VERIFIABLE with a note).

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("ext.1.5.testssl")) ]]] -->

- "TLS weakness (<lower>): <identifier>"
- "Deprecated TLS protocol offered: <identifier>"

<!-- [[[end]]] -->

`evidence_ref` testssl.sh's output artifact.

## 10. Effects on the target

`READ_ONLY`: a TLS handshake scan, no credential, no change to the target.

## 11. Per gateway

Independent of the adapter: testssl scans the HTTPS listener directly. The scan reaches whatever TLS endpoint
`base_url` names.

## 12. Configuration

No test parameter. The tool is configured under `external_tools.testssl` (`timeout_seconds`, `extra_flags`,
`expected_version`, `dev_mode`). testssl.sh is the single TLS analysis tool for this guarantee.

## 13. Remediation

Disable every deprecated protocol (SSLv3, TLS 1.0/1.1) and weak cipher (RC4, 3DES, static RSA key exchange) in the
gateway's TLS configuration, keep only TLS 1.2/1.3 with ECDHE + AES-GCM, and serve a certificate from a CA the
clients trust (NIST SP 800-52 Rev.2, ASVS v5.0.0-12.1.1).
