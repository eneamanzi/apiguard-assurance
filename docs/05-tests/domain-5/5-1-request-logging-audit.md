# 5.1 Request Logging Audit

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_5/test_5_1_request_logging_audit.py`](../../../src/tests/domain_5/test_5_1_request_logging_audit.py) ·
> **Verified:** 2026-11-17

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

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 5.1) |
|---|---|
| `request_logging_configured` | the gateway produces logs for every request (audited as: a logging plugin is enabled) |
| `secrets_not_shipped` | "sensitive values redacted", for the part the gateway decides: whether the record a shipper builds carries the credential in clear, read from the configuration (added 2026-11-17, owner) |
| left out | the other log-content checks: required fields, real source IP, log-injection resistance, secrets in bodies or in the application's own logs. They need read access to the log stream, which the tool does not have on any target; not planned (2026-10-27) |

## 3. Inputs

Two concepts read through the adapter: the configuration values (`config_values`), only to tell an empty read from
a configuration without the plugin, and the log-shipping plugins (`log_shipping`). Which plugins ship request logs
is each adapter's knowledge, so this test names no gateway (owner decision 2026-11-04; until
then a list of Kong and APISIX names was inside the test). Kong: `http-log`, `tcp-log`, `udp-log`, `loggly` (its
`file-log` and `syslog` write on the gateway's own host); APISIX: its `*-logger` and `*-logging` plugins, `syslog`,
`loggly`, `tencent-cloud-cls`, except `file-logger` (lists read on the gateways' sources 2026-11-04).

For `secrets_not_shipped`, each shipper's `request` (`ShippedRequest`): the request parts its record carries
(`header:<name>`, `query:<name>`, `cookie:<name>`, `<kind>:*` for all of a kind), those removed for all the traffic it
logs, and those removed for part of it only. And where the target's credential travels, from the run, never from the
gateway: the configured placement (`credentials`, `TargetContext.credential_placement`) and the security schemes the
specification declares (an apiKey scheme by its location and name; http, oauth2 and openIdConnect in
`Authorization`). A cookie travels by its own name and in the `Cookie` header.

## 4. Preconditions and reference responses

`Need.GATEWAY` (the Admin API). No reference responses: the configuration read is the evidence.

## 5. Probes

None: a configuration audit. `config_values` is read and pinned as evidence.

## 6. Oracle

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

Until 2026-11-16 a Kong log shipper bound to a single consumer counted as logging every request (Kong's adapter reported it GLOBAL): it is left out now, as for the limits; and the configuration values were read before the shippers, so an adapter without them could not judge. ASVS 16.3.3 (the application's security events), which a shipping plugin does not show, is no longer cited; the NIST controls are AU-4(1) and AU-9(2). `secrets_not_shipped` was added on 2026-11-17: until then a shipper writing every token in clear passed.

## 7. Outcomes

SKIP when the gateway has no such configuration, INCONCLUSIVE when it cannot be read (until 2026-11-04 a SKIP) or reads as empty. FAIL when no log-shipping plugin is
enabled among the values read, or when one ships the credential; PASS when one ships and none carries the credential.
`secrets_not_shipped` is NOT_APPLICABLE without a shipper.

## 8. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("5.1")) ]]] -->

- "No gateway plugin ships the request logs to a separate system"
- "Credential shipped in the request logs by '<plugin>'"

<!-- [[[end]]] -->

`evidence_ref` the log-shipping concept artifact.

## 9. Effects on the target

`READ_ONLY`: reads the gateway Admin API.

## 10. Per gateway

The logging plugins differ by gateway (Kong vs APISIX); the audit matches a set of known plugin names. A gateway
whose logging is configured outside the Admin API's view is a coverage limit.

Only an active plugin counts. Kong marks a plugin off with its own `enabled: false`, APISIX with `_meta.disable: true`
in the plugin's configuration; both adapters carry that state on every configuration value they report, and this
test skips the values of a disabled plugin. Until 2026-11-03 it did not, so a gateway whose only logging plugin was
switched off passed with "a logging plugin is configured".

What a record carries is each adapter's knowledge, read on the gateways' sources in the labs' containers (2026-11-17):

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

## 11. Configuration

None.

## 12. Validation

**2026-11-16, after the review**: **FAIL** on the three labs (no shipper), as before.

**`secrets_not_shipped`, 2026-11-17.** The three labs as they are: `NO_SHIPPER` (no shipper). Variants, each removed
afterwards and the lab checked back (Kong file identical and recreated; APISIX rule deleted, `setup.sh` applied
again, no global rule left, the route's plugins as before):

| Lab, change | Result |
|---|---|
| Forgejo + Kong, `http-log` on `forgejo-service` | **FAIL**, `CREDENTIAL_SHIPPED`: the query `access_token`, `token`, `sudo`, the headers `sudo`, `x-forgejo-otp` (`authorization` redacted) |
| Forgejo + Kong, the same with `custom_fields_by_lua: {request.headers.sudo: ...}` | `RECORD_NOT_STATED` (sub-test INCONCLUSIVE, the test PASS) |
| crAPI + Kong, `http-log` on `identity-service` | **PASS**, `CREDENTIAL_NOT_SHIPPED` (the only scheme is bearer, in the redacted `Authorization`) |
| Forgejo + APISIX, global `http-logger` | **FAIL**, `CREDENTIAL_SHIPPED`, `authorization` included |
| Forgejo + APISIX, global `http-logger` with `log_format: {host, status, path}` | **PASS** |
| Forgejo + APISIX, global `http-logger` and global `data-mask` removing every declared place | **PASS** |
| Forgejo + APISIX, the same with `Authorization` masked by a `regex` | `CREDENTIAL_REMOVED_IN_PART` (INCONCLUSIVE) |
| Forgejo + APISIX, global `http-logger`, the `data-mask` on `forgejo-api-route` | **FAIL** (the route's mask runs after the global logger) |
| Forgejo + APISIX, `http-logger` and `data-mask` both on `forgejo-api-route` | **PASS** |
| Forgejo + APISIX, global `kafka-logger` with `meta_format: origin` and a `log_format` `{h: $host}` | **FAIL** (origin ignores the format; before the review below, a false PASS) |
| Forgejo + APISIX, the global `data-mask` with a `_meta.filter` | `CREDENTIAL_REMOVED_IN_PART` (INCONCLUSIVE) |
| Forgejo + Kong, `http-log` and a `file-log` with `custom_fields_by_lua` on the request | `RECORD_NOT_STATED` (the field reaches the `http-log` record too) |

**An independent review** (a separate read-only pass on the code against the gateways' sources, 2026-11-17) found
five defects and three real edge cases, all fixed before the table above was run again: kafka/rocketmq `origin`
with a `log_format`, `jwt-auth`'s cookie, Kong's most specific `key-auth`, a plugin in two global rules, Kong's
custom fields shared across plugins; arrays and an empty `log_format`, cached query variables, `_meta.filter` and
`_meta.priority`, routes related by name.

**The records themselves** (the model above checked against what the gateways write, not only against their source):
a `file-log`/`file-logger` writing to `/dev/stdout` builds the same record as the shippers, and one request carrying
dummy values (`Authorization: token DUMMYSECRET1`, `Cookie: sid=DUMMYCOOKIE`, `?access_token=DUMMYSECRET2`) was sent
per case. Kong: `"authorization":"REDACTED"`, the cookie, the `Sudo` header and the query value (5 times) in clear.
APISIX: all three in clear with a global logger; the global `data-mask` (Authorization, access_token) leaves only the
cookie; the same mask on the route leaves all three (the order above); mask and logger on the route leave only the
cookie; a route `log_format` `{host, $http_authorization}` carries only `DUMMYSECRET1`. `hide_credentials` was read on
the sources, not exercised: no lab uses `key-auth` or `jwt-auth`.


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

**What each branch has been seen doing** (rule 9). Proven on a lab: `LOGS_NOT_SHIPPED` (all three), `LOGS_SHIPPED`
(Forgejo + Kong with the plugin above). Seen on a stand-in Admin API only: `NO_CONFIG_VALUE`. Not reachable with the
supported gateways: the SKIP for a gateway with no configuration values to read (both adapters read them,
`_read_config_values` in `src/core/gateway/kong.py` and `apisix.py`). `CONCEPT_NOT_ACCESSIBLE` was seen on 2026-11-15 (Forgejo + Kong, the run's
`gateway.admin.url` on a closed port): INCONCLUSIVE, "no access to configuration values".

## 13. Remediation

Enable a request-logging plugin that ships structured logs (timestamp, request id, method, path, real IP, user,
status, latency) to the log store (NIST SP 800-92, ASVS v5.0.0-16.4.3, NIST SP 800-53r5 AU-4(1)), without the
credential: a log format that leaves out the headers, query arguments and cookies carrying it, or the gateway's own
masking or hide-credentials option (ASVS v5.0.0-16.2.5).

## 14. Limitations

- What the logs contain is read only as far as the gateway's configuration decides it: whether the shipped record
  carries the credential. The fields, the real source IP, log-injection resistance and secrets in bodies need read
  access to the log stream, which the tool does not have on any target and is not planned (2026-10-27).
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

## 15. Sources

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
