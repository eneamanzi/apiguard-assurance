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

**Same group:** none. Guarantee 5.2 (real-time alerting) has no test: it needs the SIEM or an alert receiver the tool
cannot reach ([guarantee 5.2](../../06-knowledge/03-guarantees.md#52-anomalous-security-events-trigger-real-time-alerts-p2-proposed-no-test)).

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

Two concepts read through the adapter: the configuration values (`config_values`), only to tell an empty read from
a configuration without the plugin, and the log-shipping plugins (`log_shipping`). Which plugins ship request logs
is each adapter's knowledge, so this test names no gateway (owner decision 2026-11-04; until
then a list of Kong and APISIX names was inside the test). Kong: `http-log`, `tcp-log`, `udp-log`, `loggly` (its
`file-log` and `syslog` write on the gateway's own host); APISIX: its `*-logger` and `*-logging` plugins, `syslog`,
`loggly`, `tencent-cloud-cls`, except `file-logger` (lists read on the gateways' sources 2026-11-04).

## 4. Preconditions and reference responses

`Need.GATEWAY` (the Admin API). No reference responses: the configuration read is the evidence.

## 5. Probes

None: a configuration audit. `config_values` is read and pinned as evidence.

## 6. Oracle (`request_logging_configured`)

| Case | Outcome / detail | Confidence |
|---|---|---|
| a plugin the adapter reports as shipping request logs to another system is enabled (Inputs) | `ENFORCED/LOGS_SHIPPED` (a note names it) | - |
| none, among values that were read (a `file-log` writing on the gateway's own host does not count: ASVS v5.0.0-16.4.3 asks for a logically separate system) | `VIOLATION/LOGS_NOT_SHIPPED` | FIRM: a collector on the gateway's host, invisible to the Admin API, could ship the gateway's own access log |
| the read succeeded and returned **no value at all** | `NOT_VERIFIABLE/NO_CONFIG_VALUE` (a note says so) | - |
| the gateway has no configuration values to read (not supported) | SKIP | - |
| the configuration exists but cannot be read (Admin API down, access refused) | `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` (a note gives the reason) | - |

A note on every result states the log-content checks need log access and were not done.

## 7. Outcomes

SKIP when the gateway has no such configuration, INCONCLUSIVE when it cannot be read (until 2026-11-04 a SKIP) or reads as empty. FAIL when no log-shipping plugin is
enabled among the values read, PASS when one is.

## 8. Findings

"No gateway plugin ships the request logs to a separate system", `evidence_ref` the configuration concept
artifact.

## 9. Effects on the target

`READ_ONLY`: reads the gateway Admin API.

## 10. Per gateway

The logging plugins differ by gateway (Kong vs APISIX); the audit matches a set of known plugin names. A gateway
whose logging is configured outside the Admin API's view is a coverage limit.

Only an active plugin counts. Kong marks a plugin off with its own `enabled: false`, APISIX with `_meta.disable: true`
in the plugin's configuration; both adapters carry that state on every configuration value they report, and this
test skips the values of a disabled plugin. Until 2026-11-03 it did not, so a gateway whose only logging plugin was
switched off passed with "a logging plugin is configured".

## 11. Configuration

None.

## 12. Validation

Runs of 2026-10-23:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, crAPI + Kong, Forgejo + APISIX | **FAIL** | no log-shipping plugin enabled on the default labs. The gateways do write their own access log (the Kong labs set `KONG_PROXY_ACCESS_LOG=/dev/stdout`, APISIX writes nginx's), to the container's output and nowhere else: until 2026-11-04 the finding said "requests are not logged at the gateway", CERTAIN, which this contradicts |
| Forgejo + Kong, with the plugin below | **PASS** | a global `http-log` plugin is detected (`LOGS_SHIPPED`); measured again on 2026-11-04 through the adapter's log-shipping concept, the lab then put back and FAIL again |

**The case the labs lack, and how to undo it.** Add a global `http-log` plugin (any `http_endpoint`) to
`test-environments/forgejo-kong/kong/kong.yml`, reload Kong (`docker compose ... up -d --force-recreate --wait
kong`); undo with `git checkout` and the same command. The lab was checked back to FAIL. Rule 9: both sides proven;
the log-content checks are permanently outside this test (see Limitations).

**The empty read, and the false finding it used to produce** (2026-10-29). Until that date, no logging plugin
*among the values read* and no value read at all were the same case, so a gateway the adapter returned nothing for
was reported `FAIL` with the finding "No request-logging plugin on the gateway": an accusation resting on nothing.
Seen against a stand-in Admin API on `127.0.0.1` answering every endpoint with an empty collection (a local
process, no lab touched): before the fix `FAIL`, 1 finding; after it `INCONCLUSIVE`, 0 findings, with a note saying
the read was empty. The three real gateways are unchanged, still `FAIL` from 11, 25 and 15 values read.

**The disabled plugin, and the false pass it used to produce** (2026-11-03). Against a stand-in Kong Admin API on
`127.0.0.1` whose only logging plugin is `http-log` (no lab touched): with the plugin `enabled: false`, the test
reported **PASS** before the fix and reports **FAIL**, "No request-logging plugin on the gateway", after it; with the
plugin `enabled: true` it reports PASS, so the enforced branch still holds. The three real gateways carry no
disabled plugin and are unchanged.

## 13. Remediation

Enable a request-logging plugin that ships structured logs (timestamp, request id, method, path, real IP, user,
status, latency) to the log store, with sensitive values redacted (NIST SP 800-92, ASVS v5.0.0-16.3.3 and 16.4.3,
NIST SP 800-53r5 AU-2).

## 14. Limitations

- Only the presence of a logging plugin is audited, never what the logs contain. Checking fields, secret redaction,
  the real source IP or log-injection resistance needs read access to the log stream, which the tool does not have on
  any target and is not planned (2026-10-27): a gateway that logs every request into a file full of unredacted
  tokens passes this test.
- Logging configured outside the gateway's plugins (the gateway's own access log, a collector on its host, the
  application's logs, a sidecar the Admin API does not expose) is not seen: the finding says no plugin ships the
  logs, never that requests are not logged.

## 15. Sources

- NIST SP 800-92 (Guide to Computer Security Log Management): https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-92.pdf
- OWASP ASVS v5.0.0-16.3.3 (the security events of the documentation are logged, bypass attempts included) and
  v5.0.0-16.4.3 (the logs reach a logically separate system for analysis, detection and alerting), which is what a
  gateway logging plugin does: https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
- The per-entry content of a log (ASVS v5.0.0-16.2.1) is what this test cannot see, and the methodology does ask for
  it: guarantee 5.1 of the catalogue keeps that requirement, this test does not claim it.
- NIST SP 800-53 Rev.5 AU-2 (event logging): https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home
- CWE-778 Insufficient Logging: https://cwe.mitre.org/data/definitions/778.html
