# 6.4 Hardcoded Credentials Audit

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_6/test_6_4_hardcoded_credentials_audit.py`](../../../src/tests/domain_6/test_6_4_hardcoded_credentials_audit.py) ·
> **Verified:** 2026-10-23

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

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 6.4) |
|---|---|
| `debug_endpoint_no_secret` | "debug endpoint exposure: `/actuator/env` etc. must not expose credentials" (empirical) |
| `gateway_config_no_secret` | "pattern scan of the gateway config for credential formats and high-entropy values in sensitive keys" |
| left out | the Docker-image `docker history` scan and the secret-manager rotation audit (no access to a registry or a vault from the tool) |

## 3. Inputs

The debug endpoint paths to probe (`debug_endpoint_paths`, configured; none means the sub-test is not applicable).
The gateway's configuration values read through the adapter (`config_values`, `Need.GATEWAY` optional). Secret values
are masked (`SecretStr`).

## 4. Preconditions and reference responses

None for the debug probe (unauthenticated). The config scan needs a gateway; without one it is NOT_APPLICABLE.

## 5. Probes

An unauthenticated GET to each configured debug path (its body scanned for credential patterns); a read of
`config_values`, each value scanned by pattern and by a credential-named key holding a non-placeholder value.
READ_ONLY.

## 6. Oracle

**`debug_endpoint_no_secret`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a debug path answers 2xx and its body matches a credential pattern | `VIOLATION/DEBUG_SECRET` | FIRM |
| it is refused (non-2xx) | `ENFORCED/DEBUG_BLOCKED` | - |
| 2xx with no credential | `ENFORCED/DEBUG_NO_SECRET` | - |
| no debug path configured | `NOT_APPLICABLE/NO_DEBUG_PATH` | - |

**`gateway_config_no_secret`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a config value matches a credential pattern | `VIOLATION/CONFIG_SECRET` | FIRM |
| a credential-named key holds a long non-placeholder value | `VIOLATION/CONFIG_SECRET` | TENTATIVE |
| none found | `ENFORCED/CONFIG_NO_SECRET` | - |
| no gateway, or config not readable | `NOT_APPLICABLE` / `NOT_VERIFIABLE` | - |

## 7. Outcomes

FAIL on an exposed credential; PASS when the debug endpoints and the config are clean.

## 8. Findings

"Debug endpoint exposes a credential: `<path>`", "Credential pattern in gateway config: ...", "Probable plaintext
credential in gateway config: ...", each pointing to the request or the config concept artifact.

## 9. Effects on the target

`READ_ONLY`: unauthenticated reads of debug paths and a read of the gateway config.

## 10. Per gateway

The config scan reads whatever `config_values` exposes (Kong: service URLs and plugin config strings; APISIX:
equivalent). On a Kong DB-less gateway the config holds few string values, so the scan may find little; this is a
coverage limit, not a pass.

## 11. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("6.4", page=cog.inFile)) ]]] -->

Section [`tests.domain_6.test_6_4`](../../03-reference/01-configuration.md#testsdomain_6test_6_4) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `debug_endpoint_paths` | list | empty | Paths of debug or actuator endpoints to probe unauthenticated for exposed credentials (e.g. /actuator/env, /debug/vars). Empty: the debug sub-test is not applicable. |

<!-- [[[end]]] -->

## 12. Validation

Runs of 2026-10-28 (the coverage column was added when a skipped sub-test began to lower it):

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, crAPI + Kong, Forgejo + APISIX | **PASS**, `partial` | no `debug_endpoint_paths` configured, so `debug_endpoint_no_secret` judged its case `NOT_APPLICABLE` and verified nothing: the coverage is partial, because the check was never made rather than made and passed. The config scan read 11, 25 and 15 values respectively and matched no credential pattern (`gateway_config_no_secret` enforced) |
| Forgejo + Kong, a synthetic token planted in a plugin header list and then removed | **FAIL**, 1 finding | `config.add.headers[3]` of the `response-transformer` plugin held a GitHub-PAT-shaped value: `VIOLATION/CONFIG_SECRET`, FIRM, the finding naming the exact key |

Rule 9: both sides of `gateway_config_no_secret` are proven on a real gateway. The VIOLATION of
`debug_endpoint_no_secret` stays unproven: it needs a target with a debug endpoint that returns a secret.

**How many values the scan actually reads**, measured on 2026-10-28 after the review of the adapters: 11 on
Forgejo + Kong, 25 on crAPI + Kong, 15 on Forgejo + APISIX. Until that review it was **zero on every Kong
gateway**, so the ENFORCED side rested on an empty scan: the Kong reader looked for a `url` field that Kong's
Service object does not have, and the shared scanner skipped strings that are items of an array, which is the shape
a gateway plugin states a header in. The planted token above was invisible to the old reader and is the proof.

## 13. Remediation

Keep credentials in a secret manager and reference them at runtime, never in a config file or image (ASVS
v5.0.0-13.3.1, CWE-798); make debug endpoints return 401/403 or remove them in production.

## 14. Limitations

- The debug sub-test probes only the configured paths; an undocumented debug endpoint is not found here (that is
  test 0.1 / ffuf).
- The config scan sees only what the adapter's `config_values` exposes; a secret in a file the Admin API does not
  surface (Kong DB-less) is not reached.
- The semantic-key rule is a heuristic (TENTATIVE): a long non-secret value in a credential-named key is a false
  positive, a secret in a differently-named key a false negative.
- The pattern set is six shapes (credentials inside a URL, AWS access key, Stripe live and test keys, GitHub
  personal access token, PEM private key). There is no generic rule for a bearer token or an API key, so
  `Authorization: Bearer <opaque>` in a plugin header is caught only by the semantic-key rule, if the key is named
  like a credential.

## 15. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- OWASP ASVS v5.0.0-13.3.1 (secrets management): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x22-V13-Configuration.md
- NIST SP 800-53 Rev.5 section 3.7, control IA-5(7) ("no embedded unencrypted static authenticators": ensure that
  unencrypted static authenticators are not embedded in applications or other forms of static storage):
  https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home
- CWE-798 Use of Hard-coded Credentials: https://cwe.mitre.org/data/definitions/798.html
