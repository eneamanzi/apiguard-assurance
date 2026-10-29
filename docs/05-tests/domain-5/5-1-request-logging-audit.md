# 5.1 Request Logging Audit

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_5/test_5_1_request_logging_audit.py`](../../../src/tests/domain_5/test_5_1_request_logging_audit.py) ·
> **Verified:** 2026-10-23

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("5.1", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `5.1` |
| Name | Request Logging Audit |
| Domain | 5 - Visibility and Auditing |
| Priority / strategy | P1 / WHITE_BOX |
| Effect | READ_ONLY |
| CWE | CWE-778 |
| Standards | `OWASP ASVS v5.0.0-16.3.3`, `OWASP ASVS v5.0.0-16.4.3`, `NIST SP 800-92`, `NIST SP 800-53r5, Section 3.3` |
| Tags | `logging`, `auditing` |
| Prerequisites | none |
| Needs | `GATEWAY` |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** test `5.2` (visibility and auditing).

## 1. Guarantee

Every request is logged with its metadata. A PASS promises a request-logging plugin is enabled on the gateway. The
threat (NIST SP 800-92, ASVS v5.0.0-16.3.3 and 16.4.3, NIST SP 800-53r5 AU-2): without logging, a security incident
or a brute-force attempt leaves no
trail for investigation. The methodology states the limit: "without access to the logs this guarantee cannot be
checked empirically from outside", so the test audits the gateway's configuration, not the log content.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 5.1) |
|---|---|
| `request_logging_configured` | the gateway produces logs for every request (audited as: a logging plugin is enabled) |
| left out | the log-content checks: required fields, secret redaction, real source IP, log-injection resistance. All four need read access to the log stream, which the tool does not have on any target; not planned (2026-10-27) |

## 3. Inputs

The gateway's configuration values (`config_values`, read through the adapter), scanned for a known logging plugin
(Kong `http-log`/`file-log`/`syslog`/...; APISIX `http-logger`/`syslog`/...).

## 4. Preconditions and reference responses

`Need.GATEWAY` (the Admin API). No reference responses: the configuration read is the evidence.

## 5. Probes

None: a configuration audit. `config_values` is read and pinned as evidence.

## 6. Oracle (`request_logging_configured`)

| Case | Outcome / detail | Confidence |
|---|---|---|
| a known logging plugin is enabled | `ENFORCED/LOGGING_CONFIGURED` (a note names it) | CERTAIN |
| none | `VIOLATION/NO_REQUEST_LOGGING` | CERTAIN |
| the configuration cannot be read | SKIP | - |

A note on every result states the log-content checks need log access and were not done.

## 7. Outcomes

SKIP when the configuration cannot be read. FAIL when no logging plugin is enabled, PASS when one is.

## 8. Findings

"No request-logging plugin on the gateway", `evidence_ref` the configuration concept artifact.

## 9. Effects on the target

`READ_ONLY`: reads the gateway Admin API.

## 10. Per gateway

The logging plugins differ by gateway (Kong vs APISIX); the audit matches a set of known plugin names. A gateway
whose logging is configured outside the Admin API's view is a coverage limit.

## 11. Configuration

None.

## 12. Validation

Runs of 2026-10-23:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, crAPI + Kong, Forgejo + APISIX | **FAIL** | no logging plugin enabled on the default labs (a real gap) |
| Forgejo + Kong, with the plugin below | **PASS** | a global `http-log` plugin is detected (`LOGGING_CONFIGURED`) |

**The case the labs lack, and how to undo it.** Add a global `http-log` plugin (any `http_endpoint`) to
`test-environments/forgejo-kong/kong/kong.yml`, reload Kong (`docker compose ... up -d --force-recreate --wait
kong`); undo with `git checkout` and the same command. The lab was checked back to FAIL. Rule 9: both sides proven;
the log-content checks are permanently outside this test (see Limitations).

## 13. Remediation

Enable a request-logging plugin that ships structured logs (timestamp, request id, method, path, real IP, user,
status, latency) to the log store, with sensitive values redacted (NIST SP 800-92, ASVS v5.0.0-16.3.3 and 16.4.3,
NIST SP 800-53r5 AU-2).

## 14. Limitations

- Only the presence of a logging plugin is audited, never what the logs contain. Checking fields, secret redaction,
  the real source IP or log-injection resistance needs read access to the log stream, which the tool does not have on
  any target and is not planned (2026-10-27): a gateway that logs every request into a file full of unredacted
  tokens passes this test.
- Logging configured outside the gateway (at the application, or a sidecar the Admin API does not expose) is not
  seen.

## 15. Sources

- NIST SP 800-92 (Guide to Computer Security Log Management): https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-92.pdf
- OWASP ASVS v5.0.0-16.3.3 (the security events of the documentation are logged, bypass attempts included) and
  v5.0.0-16.4.3 (the logs reach a logically separate system for analysis, detection and alerting), which is what a
  gateway logging plugin does: https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
- The per-entry content of a log (ASVS v5.0.0-16.2.1) is what this test cannot see, and the methodology does ask for
  it: guarantee 5.1 of the catalogue keeps that requirement, this test does not claim it.
- NIST SP 800-53 Rev.5 AU-2 (event logging): https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home
- CWE-778 Insufficient Logging: https://cwe.mitre.org/data/definitions/778.html
