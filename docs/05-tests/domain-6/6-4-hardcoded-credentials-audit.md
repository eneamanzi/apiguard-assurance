# 6.4 Hardcoded Credentials Audit

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_6/test_6_4_hardcoded_credentials_audit.py`](../../../src/tests/domain_6/test_6_4_hardcoded_credentials_audit.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("6.4", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `6.4` |
| Name | Hardcoded Credentials Audit |
| Domain | 6 - Configuration and Hardening |
| Priority / strategy | P2 / BLACK_BOX |
| Effect | READ_ONLY |
| CWE | CWE-798 |
| Standards | `OWASP API8:2023`, `OWASP ASVS v5.0.0-13.3.1`, `NIST SP 800-53r5, Section 3.7` |
| Tags | `hardcoded-credentials`, `secret-management` |
| Prerequisites | none |
| Needs | `GATEWAY` (optional) |
| Parameters | [`tests.domain_6.test_6_4`](../../03-reference/01-configuration.md#testsdomain_6test_6_4) |

<!-- [[[end]]] -->

**Same group:** tests `6.1`, `6.2`.

## 1. Guarantee

Service credentials are not exposed through a debug endpoint nor hard-coded in the gateway configuration. A PASS
promises a probed debug endpoint returned no credential, and the gateway's configuration held none. OWASP API8:2023,
CWE-798; ASVS v5.0.0-13.3.1 (secrets in a vault, not in source or artifacts).

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 6.4) |
|---|---|
| `debug_endpoint_no_secret` | "debug endpoint exposure: `/actuator/env` etc. must not expose credentials" (empirical) |
| `gateway_config_no_secret` | "pattern scan of the gateway config for credential formats and high-entropy values in sensitive keys" |
| left out | the Docker-image `docker history` scan and the secret-manager rotation audit (no access to a registry or a vault from the tool) |

### 2.2 Preconditions and reference responses

None for the debug probe (unauthenticated). The config scan needs a gateway; without one it is NOT_APPLICABLE.

### 2.3 Probes

An unauthenticated GET to each configured debug path, or, when none is configured, to each of the tool's six paths that
expose configuration (`src/core/sensitive_paths.py`, kind CONFIGURATION: `actuator/env`, `actuator/configprops`,
`server-info`, `.env`, `.git/config`, `.git/HEAD`) under the root and each service prefix (its body scanned for
credential patterns and for credential-named keys with a real value: `KEY=VALUE` lines, JSON pairs, an actuator's
`name`/`value`); a read of
`config_values`, each value scanned by pattern and by a credential-named key holding a non-placeholder value.
READ_ONLY.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("6.4")) ]]] -->

**`debug_endpoint_no_secret`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a path answers `2xx` without a credential and its body holds a credential pattern, or a credential-named key with a real value | `VIOLATION/DEBUG_SECRET` | FIRM |
| it answers `2xx` and its body holds no credential | `ENFORCED/DEBUG_NO_SECRET` | - |
| it answers `404` or `410` | `ENFORCED/DEBUG_NOT_FOUND` | - |
| it is refused (`401`, `403`, `400`, `405`, ...) | `ENFORCED/DEBUG_BLOCKED` | - |
| it answers a redirect (not followed) or a status of no class | `NOT_VERIFIABLE/NOT_INTERPRETED` | - |

**`gateway_config_no_secret`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a gateway configuration value matches a credential pattern | `VIOLATION/CONFIG_SECRET` | FIRM |
| a credential-named key (a header's name in a header list) holds a non-placeholder value of 8 characters or more, not a secret reference | `VIOLATION/CONFIG_SECRET` | TENTATIVE |
| no value read holds a credential (secret references excepted) | `ENFORCED/CONFIG_NO_SECRET` | - |
| the read succeeded and returned no value at all | `NOT_VERIFIABLE/NO_CONFIG_VALUE` | - |
| no gateway is configured | `NOT_APPLICABLE/NO_GATEWAY` | - |
| the gateway's adapter does not read configuration values | `NOT_APPLICABLE/CONFIG_NOT_SUPPORTED` | - |
| the gateway has configuration values, and they could not be read | `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | - |

<!-- [[[end]]] -->

A value that refers to a secret kept elsewhere, written as the gateway writes it (Kong `{vault://...}`, APISIX
`$secret://...`, `$ENV://...`; the adapter states its syntax), is not reported: it is what the remediation asks for
. ..` or an actuator's unmasked `spring.datasource.password`
was `DEBUG_NO_SECRET`; a redirect counted as `DEBUG_BLOCKED`; a header in Kong's header lists
(`request-transformer` `add.headers: ["X-Api-Key:..."]`) was keyed `headers[3]`, never credential-named, while
APISIX's map form was caught; and an unreadable configuration was `CONFIG_NOT_READABLE` whether the gateway lacked
the concept (now `NOT_APPLICABLE/CONFIG_NOT_SUPPORTED`) or it could not be read (now the shared
`CONCEPT_NOT_ACCESSIBLE`).

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("6.4", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("6.4", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 15 of 15 produced cases gave the declared outcome; 1 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `debug_endpoint_no_secret/VIOLATION/DEBUG_SECRET/FIRM` | forgejo-kong: a route ~/api/debug/config$ (a configured debug path) whose pre-function answers 200 with AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE, the key built in the Lua code by concatenation so the gateway's configuration does not hold it as one string | OK |
| `debug_endpoint_no_secret/ENFORCED/DEBUG_NO_SECRET` | forgejo-kong: the lab as built: /api/v1/settings/api answers 200 with Forgejo's public API settings, no credential | OK |
| `debug_endpoint_no_secret/ENFORCED/DEBUG_NOT_FOUND` | forgejo-kong: the lab as built: ten of the configured debug paths answer 404, from Forgejo or from Kong's deny-by-default | OK |
| `debug_endpoint_no_secret/ENFORCED/DEBUG_BLOCKED` | crapi-kong: the lab as built, no debug_endpoint_paths: the default paths under /identity are refused unauthenticated by crAPI's identity service | OK |
| `debug_endpoint_no_secret/NOT_VERIFIABLE/NOT_INTERPRETED` | forgejo-kong: the only debug path configured is the deprecated read times/user-a, on which a route answers 302 itself (redirect, not followed) | OK |
| `gateway_config_no_secret/VIOLATION/CONFIG_SECRET/FIRM` | forgejo-kong: a request-transformer on forgejo-service adds the header 'X-Lab-Note:ghp_LabDummyNotARealToken000000000000000' (a GitHub-PAT shape, under a name that is not credential-named): the config scan matches the pattern | OK |
| `gateway_config_no_secret/VIOLATION/CONFIG_SECRET/TENTATIVE` | forgejo-kong: a request-transformer on forgejo-service adds the header 'X-Api-Key:lab-dummy-not-real-0001': a credential-named header with a 22-character non-placeholder value | OK |
| `gateway_config_no_secret/ENFORCED/CONFIG_NO_SECRET` | forgejo-kong: the lab as built: no Kong configuration value holds a credential | OK |
| `gateway_config_no_secret/NOT_VERIFIABLE/NO_CONFIG_VALUE` | forgejo-kong: the run's gateway.admin.url points to a stand-in Kong Admin API on 127.0.0.1 answering every endpoint with an empty collection | OK |
| `gateway_config_no_secret/NOT_APPLICABLE/NO_GATEWAY` | forgejo-kong: the run's configuration has no gateway section | OK |
| `gateway_config_no_secret/NOT_APPLICABLE/CONFIG_NOT_SUPPORTED` | not producible (code): both supported adapters read configuration values (KongGatewayAdapter and ApisixGatewayAdapter override _read_config_values); only an adapter without it reaches this guard | - |
| `gateway_config_no_secret/NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | forgejo-kong: the run's gateway.admin.url points to a closed port | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: the forgejo container stopped: Kong answers 503 on the configured debug paths it routes to Forgejo | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: the only debug path configured is the deprecated read times/user-a, on which a route answers 429 itself | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: the only debug path configured is the deprecated read times/user-a, on which a route answers 500 itself | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: the only debug path configured is the deprecated read times/user-a, on which a route waits 7 s before proxying, with the run's target.read_timeout 5.0 | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("6.4", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- **Consumer credentials are scanned on APISIX and not on Kong.** The APISIX adapter reads the consumers' plugin
  values, so a consumer's key stored in clear is flagged (TENTATIVE when only its name and length speak; APISIX can
  hold it as a secret reference instead). The Kong adapter does not read `/consumers/{id}/<plugin>`, where a Kong
  consumer's `key-auth`, `hmac-auth` or `basic-auth` secret lives, so on a production Kong those secrets are outside
  this test. The labs have no consumers, so the difference shows on none of them; adding the Kong reader would be a
  new capability and was not done.
- The debug sub-test probes the configured paths, or the six default ones; another debug endpoint is not found here
  (that is `ext.0.1.ffuf`, which searches the tool's 38 sensitive paths, without reading a credential in them). The
  defaults leave out `actuator/heapdump`, `actuator/logfile`, `actuator/httpexchanges` and `debug/vars`: configure
  them in `debug_endpoint_paths` where they may exist.
- The config scan sees only what the adapter's `config_values` exposes; a secret in a file the Admin API does not
  surface (Kong DB-less) is not reached.
- The credential-named key rule is a heuristic (TENTATIVE in the configuration, where the value is masked and judged
  by its key and length; FIRM in a served body, where it is seen): a long non-secret value in a credential-named key
  is a false positive, a secret in a differently-named key a false negative. A key ending in `token` counts, a
  fragment of one (`token_type`, `max_tokens`) does not.
- The patterns are ten shapes (credentials inside a URL, the user name may be empty; AWS access key; Stripe live and
  test keys; GitHub classic and fine-grained tokens; PEM private keys, OpenSSH, DSA and encrypted ones included;
  Slack tokens; Google API keys). There is no generic rule for a bearer token or an API key: `Authorization: Bearer
  <opaque>` is caught by the credential-named key rule (a header's name in a header list counts as its key).

## 6. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- OWASP ASVS v5.0.0-13.3.1 (secrets management): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x22-V13-Configuration.md
- NIST SP 800-53 Rev.5 section 3.7, control IA-5(7) ("no embedded unencrypted static authenticators": ensure that
  unencrypted static authenticators are not embedded in applications or other forms of static storage):
  https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home
- CWE-798 Use of Hard-coded Credentials: https://cwe.mitre.org/data/definitions/798.html

## 7. Inputs

The debug endpoint paths to probe (`debug_endpoint_paths`, configured; none, the tool's own, section 2.3). The
gateway's configuration values read through the adapter (`config_values`, `Need.GATEWAY` optional), masked
(`SecretStr`). Every credential found in a served body is registered as a secret before its record is kept, so the
outputs (evidence, report) show it redacted.

## 8. Outcomes

FAIL on an exposed credential; PASS when the debug endpoints and the config are clean.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("6.4")) ]]] -->

- "Credential pattern in gateway config: <location>"
- "Probable plaintext credential in gateway config: <location>"
- "Debug endpoint exposes a credential: <path>"

<!-- [[[end]]] -->

Each points to the request or the config concept artifact. One finding per value per configuration object: when
the same value is under several keys of one object, the strongest finding is kept (a matched pattern before a
credential-named key) and names the other keys. The debug finding cites CWE-215 and ASVS
v5.0.0-13.4.2/13.4.5; the configuration findings CWE-798 and ASVS 13.3.1; the NIST reference is SP 800-53r5's
IA family (IA-5(7), no embedded static authenticators).

## 10. Effects on the target

`READ_ONLY`: unauthenticated reads of debug paths and a read of the gateway config.

## 11. Per gateway

The config scan reads whatever `config_values` exposes (Kong: service URLs and plugin config strings; APISIX:
equivalent). On a Kong DB-less gateway the config holds few string values, so the scan may find little; this is a
coverage limit, not a pass.

## 12. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("6.4", page=cog.inFile)) ]]] -->

Section [`tests.domain_6.test_6_4`](../../03-reference/01-configuration.md#testsdomain_6test_6_4) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `debug_endpoint_paths` | list | empty | Paths of debug or actuator endpoints to probe unauthenticated for exposed credentials (e.g. /actuator/env, /debug/vars). Empty: the tool's paths that expose configuration (actuator/env, actuator/configprops, server-info, .env, .git/config, .git/HEAD), under the root and each service prefix. |

<!-- [[[end]]] -->

## 13. Remediation

Keep credentials in a secret manager and reference them at runtime, never in a config file or image (ASVS
v5.0.0-13.3.1, CWE-798); make debug endpoints return 401/403 or remove them in production.
