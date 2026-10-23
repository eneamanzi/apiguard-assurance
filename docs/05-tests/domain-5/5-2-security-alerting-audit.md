# 5.2 Security Alerting Audit

> **Audience:** analysts, contributors · **Status:** new in the test review (branch `test-review`, 2026-10-23) ·
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
| Standards | `OWASP API8:2023`, `NIST SP 800-61, Section 2.3` |
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
| deferred follow-up | those behavioural checks, once an alert webhook the tool can observe exists (shared with 7.2/7.4) |

## 3. Inputs

None available from outside: the alert rules are in the SIEM, and no alert channel is configured for the tool to
observe.

## 4. Preconditions and reference responses

Alert-rule or alert-channel access, which the tool does not have from outside.

## 5. Probes

None: the test cannot run from outside.

## 6. Oracle (`anomalous_event_alerted`)

| Case | Outcome / detail | Confidence |
|---|---|---|
| no alert-rule or alert-channel access | SKIP (the reason) | - |

## 7. Outcomes

SKIP: real-time alerting cannot be verified from outside without the SIEM's rules and a webhook receiver.

## 8. Findings

None (SKIP). A note points to the deferred behavioural checks.

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
brute-force alert within seconds, deduplication, a threshold) are a deferred follow-up that needs an alert webhook
the tool can observe.

## 13. Remediation

Configure the SIEM (or alert manager) to alert on brute force, enumeration and rate-limit events in real time, with
deduplication and tuned thresholds to avoid alert fatigue (NIST SP 800-61).

## 14. Limitations

- The test cannot verify alerting from outside: it SKIPs. A real check needs read access to the alert rules and a
  webhook receiver (the deferred follow-up).

## 15. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- NIST SP 800-61 Rev.3 section 2.3 (detection and analysis): https://csrc.nist.gov/pubs/sp/800/61/r3/final
- CWE-778 Insufficient Logging (and monitoring): https://cwe.mitre.org/data/definitions/778.html
