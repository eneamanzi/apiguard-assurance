# ext.1.5.testssl / ext.1.5.sslyze TLS Analysis

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0) · **Source of truth:**
> [`src/external_tests/ext_test_1_5_tls_analysis.py`](../../../../src/external_tests/ext_test_1_5_tls_analysis.py),
> [`src/connectors/testssl.py`](../../../../src/connectors/testssl.py), [`src/connectors/sslyze.py`](../../../../src/connectors/sslyze.py) ·
> **Verified:** 2026-10-05

Two independent tests in the same module, same oracle, different tools. Both appear in the report.

| | `ext.1.5.testssl` | `ext.1.5.sslyze` |
|---|---|---|
| Name | TLS Stack Analysis (testssl.sh) | TLS Stack Analysis (sslyze) |
| Domain | 1 - Identity and Authentication | same |
| Priority / strategy | P2 / WHITE_BOX (no Admin API needed) | same |
| CWE | CWE-326 | same |
| Tool | testssl.sh 3.2.3 (subprocess, `./tools/testssl/` or `PATH`) | sslyze `>=6.3,<7` (Python library, extra `[sslyze]`, AGPL v3) |
| Configuration | [`external_tools.testssl`](../../../reference/configuration.md#external_tools) | [`external_tools.sslyze`](../../../reference/configuration.md#external_tools) |
| Companion test | [`1.5`](../../domain-1/1-5-insecure-credential-transport.md) (HTTP redirect, HSTS) | same |

## What it checks

The TLS stack of `target.base_url`: protocol versions, cipher suites, certificate chain and known TLS
vulnerabilities. Test 1.5 covers the HTTP-level part of the same guarantee.

## How it works

**testssl.sh** runs against `host:port` of the base URL, e.g.
`testssl.sh --quiet --color 0 --connect-timeout 10 localhost:8443` (flags from `extra_flags`), with JSON output.
Severities are assigned by testssl.sh itself.

**sslyze** runs its scan through the Python API; the connector maps each result to a fixed severity:

| Check id | Severity |
|---|---|
| `ssl_2_0`, `heartbleed`, `robot_strong_oracle` | CRITICAL |
| `ssl_3_0`, `robot_weak_oracle`, `openssl_ccs_injection`, `client_renegotiation_dos`, `cert_chain_not_trusted`, `cert_sha1_signature` | HIGH |
| `tls_1_0`, `tls_1_1`, `insecure_renegotiation`, `tls_compression`, `tls_1_3_early_data`, `tls_fallback_scsv_missing`, `hsts_missing`, `hsts_max_age_too_short` | MEDIUM |

**Oracle (both tests):**

| Severity | Result |
|---|---|
| `CRITICAL`, `HIGH` | One Finding each, titled `[Critical] TLS Issue: <id>` (testssl) or `[HIGH] TLS Issue: <id>` (sslyze) |
| `MEDIUM`, `WARN` | One InfoNote each (`[Medium] TLS observation: <id>` for testssl) |
| anything else (`LOW`, `INFO`, `OK`, …) | Ignored |

## Outcomes

| Status | When |
|---|---|
| PASS | No CRITICAL/HIGH item (MEDIUM/WARN listed as InfoNotes). |
| FAIL | At least one CRITICAL/HIGH item. |
| SKIP | Tool enabled but not available. |
| ERROR | Tool failure or `timeout_seconds` exceeded. |
| (absent) | Tool disabled: not scheduled. |

References: OWASP-API2:2023, NIST-SP-800-52-Rev2, OWASP-ASVS-v5.0.0-V14.2.1, OWASP-ASVS-v5.0.0-V12.1.2.
Raw tool output: `evidence.json` (pinned artefact), `outputs/tools/`, `tool_artifact` in the JSON report.

Real run on the Forgejo + Kong lab (self-signed certificate), 2026-10-05: testssl FAIL with
`cert_chain_of_trust`, `cert_revocation`, `overall_grade`; sslyze FAIL with `cert_chain_not_trusted`.

## Coverage against the methodology

Source: [`methodology.it.md` §1.5](../../../knowledge/methodology/methodology.it.md).

| Methodology item | Status |
|---|---|
| Only TLS 1.2 / 1.3 enabled | Detected, but with sslyze TLS 1.0/1.1 support is **MEDIUM → InfoNote, not FAIL**. With testssl it depends on testssl's own severity. |
| Cipher suites with forward secrecy and AEAD | testssl only (sslyze checks listed above do not include a cipher-suite rating). |
| Certificate validity and trust | Both. |
| Certificate Transparency SCTs | Depends on testssl output; no dedicated check in the sslyze connector. |

## Why it exists

Same guarantee as [1.5](../../domain-1/1-5-insecure-credential-transport.md). Tooling decision
([`decisions.it.md` §1.5](../../../knowledge/tools/decisions.it.md)): reproducing TLS handshake analysis in Python
would require hundreds of custom handshakes; testssl.sh is the de facto standard, sslyze is the library-based
alternative usable where the shell script cannot run.

## Limitations

- The methodology requires TLS 1.2+ only; the sslyze oracle does not fail on TLS 1.0/1.1.
- `ext.1.5.sslyze` depends on an AGPL v3 library (Q-11).
- The module docstring still mentions a `testssl_binary_path` setting of test 1.5 that no longer exists.

## See also

- [`1.5 Insecure credential transport`](../../domain-1/1-5-insecure-credential-transport.md)
- [`../../reference/compatibility.md`](../../../reference/compatibility.md#external-tools)
