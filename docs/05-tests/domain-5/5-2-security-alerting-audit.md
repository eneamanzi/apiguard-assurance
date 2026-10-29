# 5.2 Security Alerting Audit

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_5/test_5_2_security_alerting_audit.py`](../../../src/tests/domain_5/test_5_2_security_alerting_audit.py) ·
> **Verified:** 2026-10-23

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("5.2", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `5.2` |
| Name | Security Alerting Audit |
| Domain | 5 - Visibility and Auditing |
| Priority / strategy | P2 / WHITE_BOX |
| Effect | READ_ONLY |
| CWE | CWE-778 |
| Standards | `OWASP API8:2023`, `NIST SP 800-61r3, Section 3.2` |
| Tags | `alerting`, `monitoring` |
| Prerequisites | none |
| Needs | - |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** test `5.1` (visibility and auditing).

## 1. Guarantee

Anomalous security events (brute force, enumeration, rate-limit hits) trigger real-time alerts. The threat (NIST SP
800-61): events are logged but no one is alerted, and a breach is found weeks later. The methodology says this is
"only partly checkable from outside": alerting lives in the SIEM or the notification channel, and observing an alert
needs a webhook receiver.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 5.2) |
|---|---|
| `anomalous_event_alerted` | the brute-force alert, deduplication and threshold checks: all need alert-rule access and a webhook receiver |
| left out | those behavioural checks: each needs an alert receiver the tool can observe, which does not exist and is not planned (2026-10-27) |

## 3. Inputs

Two things the tool would need and has no interface for: the alert rules (a SIEM, Grafana Alert Manager or
CloudWatch alarms) and an alert channel it can watch. Neither is part of a gateway's admin plane, so no adapter
concept exposes them.

## 4. Preconditions and reference responses

Read access to the alert rules, or a webhook the tool can receive on. No reference responses: there is nothing to
calibrate against.

## 5. Probes

None. Provoking an alert would need the events that trigger it (a burst of failed logins) **and** a receiver to
observe the alert on; the events alone prove nothing, so the test does not send them.

## 6. Oracle (`anomalous_event_alerted`)

| Case | Outcome / detail | Confidence |
|---|---|---|
| no alert-rule or alert-channel access | SKIP (the reason) | - |

## 7. Outcomes

Always SKIP today, with the reason. The test exists so that the guarantee appears in the report as unverified
instead of silently missing from it: a reader sees that alerting was not checked, and why.

## 8. Findings

None (SKIP). A note names the behavioural checks the test cannot make.

## 9. Effects on the target

`READ_ONLY`: the test sends nothing.

## 10. Per gateway

Independent of the gateway: alerting is not a gateway function; it is the monitoring stack's.

## 11. Configuration

None.

## 12. Validation

Runs of 2026-10-23:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, crAPI + Kong, Forgejo + APISIX | **SKIP** | no alert-rule or alert-channel access; alerting cannot be verified from outside |

Rule 9: the guarantee is out of reach from outside on every lab (SKIP with the reason). The behavioural checks (a
brute-force alert within seconds, deduplication, a threshold) need an alert receiver the tool can observe; that
receiver is not planned (2026-10-27), so the SKIP is the test's permanent answer, not a temporary one.

## 13. Remediation

Configure the SIEM (or alert manager) to alert on brute force, enumeration and rate-limit events in real time, with
deduplication and tuned thresholds to avoid alert fatigue (NIST SP 800-61).

## 14. Limitations

- The whole guarantee is out of reach from outside, so the test verifies nothing: a SKIP here is neither a pass nor
  a fail, it is an admitted gap.
- Even with the alert rules readable, reading them would prove a rule exists, not that an alert is delivered in
  time; that needs an alert receiver the tool can observe, which is not planned (2026-10-27).

## 15. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- NIST SP 800-61 Rev.3 section 3.2 (incident response; CSF outcome DE.AE-06, "information on adverse events is
  provided to authorized staff and tools", whose recommendation is to generate alerts and deliver them to the
  response tools and staff): https://csrc.nist.gov/pubs/sp/800/61/r3/final
- CWE-778 Insufficient Logging (and monitoring): https://cwe.mitre.org/data/definitions/778.html
