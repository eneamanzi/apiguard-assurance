# 5.1 Request Logging Audit

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_5/test_5_1_request_logging_audit.py`](../../../src/tests/domain_5/test_5_1_request_logging_audit.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("5.1", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `5.1` |
| Name | Request Logging Audit |
| Domain | 5 - Visibility and Auditing |
| Priority / strategy | P1 / WHITE_BOX |
| Effect | READ_ONLY |
| CWE | CWE-778 |
| Standards | `OWASP ASVS v5.0.0-16.4.3`, `NIST SP 800-92`, `NIST SP 800-53r5, Section 3.3` |
| Tags | `logging`, `auditing` |
| Prerequisites | none |
| Needs | `GATEWAY` |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** none. Guarantee 5.2 (real-time alerting) has no test: it needs the SIEM or an alert receiver the tool
cannot reach ([guarantee 5.2](../../06-knowledge/03-guarantees.md#52-anomalous-security-events-trigger-real-time-alerts-p2-proposed-no-test)).

## 1. Guarantee

Every request is logged with its metadata. A PASS promises a plugin shipping the request logs to a separate system is
enabled on the gateway, and that the record it ships does not carry the target's credential in clear. The threat
(NIST SP 800-92, ASVS v5.0.0-16.4.3, NIST SP 800-53r5 AU-4(1), AU-9(2)): without logs on a separate system, a security
incident or a brute-force attempt leaves no trail for investigation; and a log store holding credentials (ASVS
v5.0.0-16.2.5, CWE-532) hands them to whoever reads it. The methodology states the limit: "without access to the logs
this guarantee cannot be checked empirically from outside", so the test audits the gateway's configuration: what it
ships, and what of the request the gateway puts in the record.

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 5.1) |
|---|---|
| `request_logging_configured` | the gateway produces logs for every request (audited as: a logging plugin is enabled) |
| `secrets_not_shipped` | "sensitive values redacted", for the part the gateway decides: whether the record a shipper builds carries the credential in clear, read from the configuration |
| left out | the other log-content checks: required fields, real source IP, log-injection resistance, secrets in bodies or in the application's own logs. They need read access to the log stream, which the tool does not have on any target; not planned |

### 2.2 Preconditions and reference responses

`Need.GATEWAY` (the Admin API). No reference responses: the configuration read is the evidence.

### 2.3 Probes

None: a configuration audit. `config_values` is read and pinned as evidence.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("5.1")) ]]] -->

**`request_logging_configured`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| an enabled plugin ships the request logs of every client to another system | `ENFORCED/LOGS_SHIPPED` | - |
| no such plugin enabled (one bound to a single consumer does not count), among configuration values that were read | `VIOLATION/LOGS_NOT_SHIPPED` | FIRM |
| no shipper, and the configuration read returned no value at all | `NOT_VERIFIABLE/NO_CONFIG_VALUE` | - |
| the gateway has the concept the test reads, and it could not be read (one rule for every test that reads one) | `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | - |

**`secrets_not_shipped`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| an enabled shipper's record carries a part of the request where the credential travels (the configured placement, a security scheme of the specification), and nothing removes it for all the traffic it logs (FIRM: a plugin rewriting the request, or operator code, is not read) | `VIOLATION/CREDENTIAL_SHIPPED` | FIRM |
| the record carries it, and a setting removes it for part of that traffic only, or with a pattern that may leave part of it | `NOT_VERIFIABLE/CREDENTIAL_REMOVED_IN_PART` | - |
| the record carries none of those parts, or they are removed for all its traffic | `ENFORCED/CREDENTIAL_NOT_SHIPPED` | - |
| the gateway does not state what the record carries (operator code builds it) | `NOT_VERIFIABLE/RECORD_NOT_STATED` | - |
| neither the configuration nor the specification says where a credential travels | `NOT_VERIFIABLE/CREDENTIAL_PLACE_UNKNOWN` | - |
| no enabled shipper | `NOT_APPLICABLE/NO_SHIPPER` | - |
| the gateway has the concept the test reads, and it could not be read (one rule for every test that reads one) | `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | - |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("5.1", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 11 of 11 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `request_logging_configured/ENFORCED/LOGS_SHIPPED` | forgejo-kong: an http-log plugin (endpoint on a closed local port) on forgejo-service | OK |
| `request_logging_configured/VIOLATION/LOGS_NOT_SHIPPED/FIRM` | forgejo-kong: the lab as built: no log-shipping plugin among the values read | OK |
| `request_logging_configured/NOT_VERIFIABLE/NO_CONFIG_VALUE` | forgejo-kong: the run's gateway.admin.url points to a stand-in Kong Admin API on 127.0.0.1 answering every endpoint with an empty collection | OK |
| `request_logging_configured/NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | forgejo-kong: the run's gateway.admin.url points to a closed port | OK |
| `secrets_not_shipped/VIOLATION/CREDENTIAL_SHIPPED/FIRM` | forgejo-kong: an http-log plugin on forgejo-service: Kong's record carries the query access_token, token, sudo and the headers sudo, x-forgejo-otp, which the specification declares | OK |
| `secrets_not_shipped/NOT_VERIFIABLE/CREDENTIAL_REMOVED_IN_PART` | forgejo-apisix: a global rule with http-logger and a data-mask removing every place the specification declares, Authorization masked by a regex | OK |
| `secrets_not_shipped/ENFORCED/CREDENTIAL_NOT_SHIPPED` | crapi-kong: an http-log plugin on crAPI's identity-service: the only scheme is bearer, in Authorization, which Kong's record redacts | OK |
| `secrets_not_shipped/NOT_VERIFIABLE/RECORD_NOT_STATED` | forgejo-kong: an http-log plugin on forgejo-service with custom_fields_by_lua setting request.headers.sudo | OK |
| `secrets_not_shipped/NOT_VERIFIABLE/CREDENTIAL_PLACE_UNKNOWN` | forgejo-kong: an http-log plugin on forgejo-service, a run without credentials, and a local copy of Forgejo's specification with no security definitions | OK |
| `secrets_not_shipped/NOT_APPLICABLE/NO_SHIPPER` | forgejo-kong: the lab as built: no log-shipping plugin | OK |
| `secrets_not_shipped/NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | forgejo-kong: the run's gateway.admin.url points to a closed port | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("5.1", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- What the logs contain is read only as far as the gateway's configuration decides it: whether the shipped record
  carries the credential. The fields, the real source IP, log-injection resistance and secrets in bodies need read
  access to the log stream, which the tool does not have on any target and is not planned.
- Logging configured outside the gateway's plugins (the gateway's own access log, a collector on its host, the
  application's logs, a sidecar the Admin API does not expose) is not seen: the finding says no plugin ships the
  logs, never that requests are not logged.
- One shipper on any service passes the test: whether every route is logged is not judged.
- `secrets_not_shipped` reads the gateway's record and the settings that take a part out of it (Kong: its redaction,
  `key-auth`'s `hide_credentials`, `custom_fields_by_lua`; APISIX: `log_format`, `data-mask`, `hide_credentials`).
  A plugin that rewrites the request otherwise (Kong `request-transformer`, APISIX `proxy-rewrite`), Lua code calling
  `kong.log.set_serialize_value`, or a pipeline masking downstream is not read: hence FIRM.
- A setting on another scope is related only when exact: a Kong `key-auth` on a Service and a shipper on one of its
  Routes count as removed in part (NOT_VERIFIABLE), not removed.
- Names are compared lowercased: a query argument or cookie whose name differs from the credential's only in case is
  taken as the same one (query and cookie names are case-sensitive in both gateways' removers).
- Every security scheme the specification declares is taken as carrying a credential: a scheme carrying something
  else (Forgejo's `Sudo` names a user) is listed too. A credential in the request body (a login) is not judged.

## 6. Sources

- NIST SP 800-92 (Guide to Computer Security Log Management): https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-92.pdf
- OWASP ASVS v5.0.0-16.4.3 (the logs reach a logically separate system for analysis, detection and alerting), which is what a
  gateway logging plugin does: https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
- OWASP ASVS v5.0.0-16.2.5 ("it may not be allowed to log certain data, such as credentials or payment details.
  Other data, such as session tokens, may only be logged by being hashed or masked, either in full or partially"),
  same page; CWE-532: https://cwe.mitre.org/data/definitions/532.html
- The per-entry content of a log (ASVS v5.0.0-16.2.1) is what this test cannot see, and the methodology does ask for
  it: guarantee 5.1 of the catalogue keeps that requirement, this test does not claim it.
- NIST SP 800-53 Rev.5 AU-4(1) (transfer to alternate storage) and AU-9(2) (store on separate physical systems or
  components): https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home
- CWE-778 Insufficient Logging: https://cwe.mitre.org/data/definitions/778.html

## 7. Inputs

Two concepts read through the adapter: the configuration values (`config_values`), only to tell an empty read from
a configuration without the plugin, and the log-shipping plugins (`log_shipping`). Which plugins ship request logs
is each adapter's knowledge, so this test names no gateway. Kong: `http-log`, `tcp-log`, `udp-log`, `loggly` (its
`file-log` and `syslog` write on the gateway's own host); APISIX: its `*-logger` and `*-logging` plugins, `syslog`,
`loggly`, `tencent-cloud-cls`, except `file-logger` (lists read on the gateways' sources).

For `secrets_not_shipped`, each shipper's `request` (`ShippedRequest`): the request parts its record carries
(`header:<name>`, `query:<name>`, `cookie:<name>`, `<kind>:*` for all of a kind), those removed for all the traffic it
logs, and those removed for part of it only. And where the target's credential travels, from the run, never from the
gateway: the configured placement (`credentials`, `TargetContext.credential_placement`) and the security schemes the
specification declares (an apiKey scheme by its location and name; http, oauth2 and openIdConnect in
`Authorization`). A cookie travels by its own name and in the `Cookie` header.

## 8. Outcomes

SKIP when the gateway has no such configuration, INCONCLUSIVE when it cannot be read or reads as empty. FAIL when no log-shipping plugin is
enabled among the values read, or when one ships the credential; PASS when one ships and none carries the credential.
`secrets_not_shipped` is NOT_APPLICABLE without a shipper.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("5.1")) ]]] -->

- "No gateway plugin ships the request logs to a separate system"
- "Credential shipped in the request logs by '<plugin>'"

<!-- [[[end]]] -->

`evidence_ref` the log-shipping concept artifact.

## 10. Effects on the target

`READ_ONLY`: reads the gateway Admin API.

## 11. Per gateway

The logging plugins differ by gateway (Kong vs APISIX); the audit matches a set of known plugin names. A gateway
whose logging is configured outside the Admin API's view is a coverage limit.

Only an active plugin counts. Kong marks a plugin off with its own `enabled: false`, APISIX with `_meta.disable: true`
in the plugin's configuration; both adapters carry that state on every configuration value they report, and this
test skips the values of a disabled plugin. 
What a record carries is each adapter's knowledge, read on the gateways' sources in the labs' containers:

- **Kong 3.9.3** (`kong/pdk/log.lua`, `serialize`): every request header, with `authorization` and
  `proxy-authorization` replaced by `REDACTED`; the query string as `querystring` and inside `uri` and `url`, the URI
  as received. `key-auth` with `hide_credentials` clears its `key_names` headers before the log phase; the query
  argument it clears stays in `uri`. Kong runs one instance of a plugin per request, the most specific
  (`kong/runloop/plugins_iterator.lua`, `lookup_cfg`), so when another `key-auth` does not hide, the hiding one counts
  as removing in part only. A `custom_fields_by_lua` key on `request` or `upstream_uri`, on any log plugin, makes every
  shipper's record not stated: the value is kept on the request and applied by every later `serialize()`.
- **APISIX 3.19.0** (`apisix/utils/log-util.lua`, `get_log_entry`): by default every header and the query string in
  `uri` and `url`; `kafka-logger`/`rocketmq-logger` with `meta_format: origin` ship the raw request line, which no
  mask rewrites; `google-cloud-logging` without a `log_format` ships the URL and the User-Agent only; a `log_format`
  (the plugin's, even empty, else its plugin metadata when not empty) ships only the variables it names, nested
  objects and arrays included, and `log_format_extra` adds its own; `meta_format: origin` ignores both.
  `data-mask` (priority 1500, log phase) removes a header or query argument before the loggers of its scope; the
  global rules run before the route's plugins (`apisix/init.lua`, `common_phase`), so a route's `data-mask` comes after
  a global logger. `hide_credentials` (`key-auth`: the configured header and query argument; `jwt-auth`: those and its
  cookie, taken out of the `Cookie` header; `basic-auth`, `hmac-auth`, `ldap-auth`: `Authorization`) clears the header
  before any log; the URI as received keeps the query. Variables are cached on the request (`core/ctx.lua`, all but
  `args`): a `$http_<name>` after `hide_credentials`, a `$query_string` or `$arg_<name>` after either remover, may keep
  the value, so those cases are removed in part only; a `$cookie_<name>` keeps it. A remover with `_meta.filter`
  (part of the traffic) or a `_meta.priority`, or a logger with its own priority, removes in part only. A plugin in
  more than one global rule runs from none of them (`apisix/plugin.lua`, `merge_global_rules`); the 3.19 Admin API
  refuses such a rule ("already exists in global rule"), so only a configuration loaded otherwise has it. Settings
  are related to a route by its id, not its name.

## 12. Configuration

None.

## 13. Remediation

Enable a request-logging plugin that ships structured logs (timestamp, request id, method, path, real IP, user,
status, latency) to the log store (NIST SP 800-92, ASVS v5.0.0-16.4.3, NIST SP 800-53r5 AU-4(1)), without the
credential: a log format that leaves out the headers, query arguments and cookies carrying it, or the gateway's own
masking or hide-credentials option (ASVS v5.0.0-16.2.5).
