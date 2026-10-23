# Group H: guarantees 5.1, 5.2 (working file)

> **Audience:** the owner and me, during the review. Method: the six phases in
> [`test-review.md`](../test-review.md) (How we work).

| Phase | State |
|---|---|
| 1. Collection | done 2026-10-23 (below) |
| 2. Design | done 2026-10-23; owner decisions below |
| 3. Code | done 2026-10-23 |
| 4. Proof | done 2026-10-23 (three labs + an announced Kong http-log plugin) |
| 5. Self-review | done 2026-10-23 |
| 6. Documentation | done 2026-10-23 |

### Results (2026-10-23)

5.1 FAIL on the three default labs (no logging plugin); PASS on forgejo-kong with an announced, reverted `http-log` plugin (ENFORCED/LOGGING_CONFIGURED). 5.2 SKIP on all (alerting not verifiable from outside). The log-content checks (5.1) and the behavioural alert checks (5.2) are deferred follow-ups. ASVS 16.2.1 verified on source.

### Decided (owner, 2026-10-23)

1. **Config audit now, content later.** 5.1 audits the gateway's logging-plugin presence; the log-content checks are
   NOT_VERIFIABLE and a deferred follow-up. 5.2 SKIPs (no alert/SIEM access from outside), the alert checks deferred.
2. **Read via `config_values`** (no new logging concept).
3. **Announced Kong `http-log` plugin** to show 5.1's enforced side.

Group H is visibility and auditing: 5.1 every request is logged, 5.2 anomalous events raise alerts. No test exists
on `main` (domain 5 is empty).

## Phase 1: collection (2026-10-23)

### The guarantees, and the hard limit

- **5.1** (NIST SP 800-92, ASVS v5.0.0-16.2.1): the gateway logs every request with its metadata (timestamp, request
  id, method, path, real IP, user, status, latency), sensitive data redacted. The methodology states plainly: "without
  access to the logs this guarantee cannot be checked empirically from outside."
- **5.2** (NIST SP 800-61, ASVS v5.0.0-7.1.1): security events (brute force, enumeration) raise real-time alerts to a
  SIEM or a channel. The methodology: "only partly checkable from outside"; it needs read access to the alert rules
  and a webhook receiver.

Both prerequisites (a log aggregator, a SIEM, an alert webhook) are things the tool does not have from outside. So
what the tool can verify is the **gateway's configuration**, not the log content or the alerts themselves.

### What the gateway exposes

`config_values` (read through the adapter) lists the enabled plugins and their config strings. A **logging plugin**
(Kong: `http-log`, `file-log`, `tcp-log`, `udp-log`, `syslog`, `datadog`, ...; APISIX: `http-logger`, `syslog`,
`kafka-logger`, ...) is detectable there by name. There is no alerting plugin on a typical gateway: alerting lives in
the SIEM. No logging or alerting concept exists on the adapter yet; `config_values` is enough to detect a logging
plugin.

The labs: Kong DB-less with no logging plugin configured (to confirm in the run); so 5.1's config audit will likely
find none (a real gap) and 5.2 has nothing to read.

## Phase 2: design (presented 2026-10-23)

### The boundary (rule 10) and the honest scope

| Question | Test | Verifiable from outside? |
|---|---|---|
| is a **request-logging** plugin configured on the gateway? | **5.1** | yes (config audit) |
| are the log **fields/redaction/real-IP/injection** correct? | 5.1 | no (needs log access) -> NOT_VERIFIABLE |
| do security events raise **alerts**? | **5.2** | no (needs the SIEM / an alert webhook) -> SKIP |

### Compact design

**5.1 Request Logging.** WHITE_BOX, `Need.GATEWAY`, READ_ONLY. NIST SP 800-92, ASVS v5.0.0-16.2.1, CWE-778
(Insufficient Logging). Sub-test `request_logging_configured`: read `config_values`, detect a known logging plugin;
one enabled -> ENFORCED/LOGGING_CONFIGURED (a note naming it); none -> VIOLATION/NO_REQUEST_LOGGING. The log-content
checks (redaction, real IP, injection, the required fields) are **not verifiable from outside** and are a deferred
follow-up (they need the operator to point the tool at the logs); the page states this plainly rather than faking a
pass.

**5.2 Security Alerting.** The gateway does not alert; alerting is the SIEM's, which the tool cannot read from
outside. 5.2 is **SKIP** with the reason (no alert-rule or webhook access), unless the operator supplies an alert
channel the tool can observe. Documented honestly; the behavioural alert tests (brute-force alert, deduplication,
threshold) are a deferred follow-up that needs a webhook receiver (shared with 7.2/7.4's out-of-band listener).

### The three situations (rule 9)

- **5.1 present (enforced):** a lab with a logging plugin (a documented, reversible Kong `http-log` plugin, announced).
- **5.1 absent (violation):** the default labs (no logging plugin) -> VIOLATION/NO_REQUEST_LOGGING.
- **5.1 not verifiable:** the log-content checks (always, from outside).
- **5.2:** SKIP on every lab (no alert access).

### Decisions for the owner (phase-2 go-ahead)

1. **Is the honest scope acceptable?** 5.1 audits the gateway's logging-plugin presence (the verifiable part) and
   reports the content checks NOT_VERIFIABLE; 5.2 SKIPs (not verifiable from outside). The alternative is to add now
   an **optional log/SIEM-access input** (a log endpoint or file the tool reads, a webhook receiver for alerts) so the
   content and alert checks can run; that is a sizeable new input. My recommendation: **ship the config-audit 5.1 and
   the honest 5.2 SKIP now**, and keep the log/SIEM-access content and alert checks as a deferred follow-up. Your call.
2. **A logging concept, or read via `config_values`?** My recommendation: read via `config_values` (no new concept);
   a dedicated `logging` concept can come with the deferred content checks.
3. **A lab change** (a Kong `http-log` plugin) to show 5.1's enforced side (rule 9), announced. Confirm, or leave the
   enforced side documented and show only the default-labs violation.
