# Connections and TLS - Design (Q-34, TLS part)

> **Audience:** project owner, Claude Code · **Status:** decided with the owner point by point (section 5,
> 2026-10-14) · **Plan:** block 7+8, last open item ([`plan.md`](plan.md)) · **Created:** 2026-10-14

## 1. Why

The tool runs on real systems, where its connections are often protected: an internal certificate authority, a
company proxy that inspects HTTPS, an Admin API that asks for a client certificate (mutual TLS) and a key. Today it
handles only the key (`target.admin_api_headers`, verified on APISIX). Inventory of its connections:

| Connection | Code | Certificate check | Internal authority | Client certificate |
|---|---|---|---|---|
| Requests to the API (the tests) | `src/core/client.py` (`httpx.Client`) | on/off, `target.verify_tls` | no | no |
| Test 1.5 HTTP redirect probe | `test_1_5_...py` (`httpx.get`) | same `target.verify_tls` | no | no |
| Specification download (`openapi_spec_url`) | `src/discovery/openapi.py`: prance, `requests.get(url)` with no TLS settings and no timeout ([prance `util/url.py`](https://github.com/RonnyPfannschmidt/prance/blob/main/prance/util/url.py)) | always on | no | no |
| `generate-seed` specification download | `src/discovery/seed_generator.py` (`httpx.get`) | always on | no | no |
| Gateway Admin API, health API | `src/core/gateway/base.py` (`httpx.Client`) | always on, no setting | no | no |
| External tools | testssl.sh, sslyze judge the target's certificate; nuclei scans | trust: Mozilla's list | - | - |

Default trust today: httpx uses the `certifi` bundle (Mozilla's list), not the operating system's store
(`httpx/_config.py`); a company authority installed on the machine by its IT, or a proxy inspecting HTTPS, is not
trusted, where a browser works.

## 2. Concepts (for the user documentation)

| Term | Meaning |
|---|---|
| HTTPS | HTTP inside an encrypted tunnel (TLS) |
| Certificate | The server's identity document: its name and who issued it |
| Certificate authority (CA) | Who issues certificates; systems trust a list of public ones |
| PKI | Public key infrastructure: authorities, certificates, keys and their rules |
| Verified HTTPS | The client checks that the certificate comes from a trusted authority and carries the name it called |
| Self-signed certificate | Issued by the server itself; no authority vouches for it |
| Internal CA | A company's own authority, unknown outside |
| `ca_bundle` | A file with the certificates of the authorities to trust for this connection, instead of the default ones |
| `verify: false` | No certificate check: encrypted, but an impostor is accepted |
| Mutual TLS (mTLS) | The client shows a certificate too; without a valid one the server refuses the connection |
| Key in a header | A password inside the connection (`X-API-KEY`): what the client may do; needs HTTPS |

## 3. Facts checked

- httpx 0.28.1 (installed): a custom authority and a client certificate go through an `ssl.SSLContext`
  ([httpx SSL guide](https://www.python-httpx.org/advanced/ssl/)); its default context loads `certifi`, or
  `SSL_CERT_FILE` / `SSL_CERT_DIR` when set (`httpx/_config.py`).
- pip 24.2 and later trust the operating system's store through `truststore` (Python 3.10+)
  ([pip HTTPS certificates](https://pip.pypa.io/en/latest/topics/https-certificates/),
  [truststore](https://pypi.org/project/truststore/)).
- Kong's Admin API listens on HTTP and HTTPS by default (`8001`, `8444 ssl`); the current Docker guide uses both
  ([configuration](https://developer.konghq.com/gateway/configuration/),
  [Docker Compose install](https://developer.konghq.com/gateway/install/docker/)); the labs set only HTTP. Kong OSS
  has no mTLS and no key for the Admin API.
- APISIX: `https_admin` with `admin_api_mtls` (`admin_ssl_cert`, `admin_ssl_cert_key`, `admin_ssl_ca_cert` for client
  certificates), one Admin API listener
  ([config.yaml.example, 3.19](https://raw.githubusercontent.com/apache/apisix/release/3.19/conf/config.yaml.example)).
- testssl.sh accepts `--add-ca`; sslyze 6.3.1 accepts `CertificateInfoExtraArgument(custom_ca_file=...)`.
- On the Forgejo + Kong lab the TLS findings of the external tools are about trust: sslyze `cert_chain_not_trusted`;
  testssl `cert_chain_of_trust`, `cert_revocation`, `overall_grade`.
- The lab certificate (`forgejo-kong/certs/server.crt`, self-signed, names `localhost` and `127.0.0.1`) and its
  private key are committed on purpose today.

## 4. Boundaries (kept out, each can be added later without changing the shape)

A password on the client key; a warning before a certificate expires (the TLS error already names an expired one);
`validate-config` trying the connections; certificate pinning; a minimum TLS version; a proxy per connection.

## 5. Decisions (one at a time with the owner)

### 5.1 Configuration by connection - decided (choice delegated by the owner, 2026-10-14)

Every party the tool talks to is a section with the same shape (`url`, `tls`, and what that party needs), instead of
keys with a prefix under `target`. Reasons: no repeated prefixes; one connection model defined once and reused; the
same idea written the same way everywhere. Cost accepted by the owner: every configuration changes, before 1.0.0, in
one breaking change with the TLS keys.

```yaml
target:                      # the API under test
  base_url: "https://api.example.com"
  tls: { ... }
  path_seed: { ... }

specification:               # the OpenAPI document
  url: "https://docs.example.com/openapi.json"   # or path: "./openapi.json"
  tls: { ... }

gateway:                     # optional: the WHITE_BOX configuration audits
  adapter: apisix
  admin:
    url: "https://gw-admin.internal:9180"
    headers: { X-API-KEY: "${APISIX_VIEWER_KEY}" }
    tls: { ... }
  health:
    url: "http://127.0.0.1:9090"
    tls: { ... }
```

Each `tls` is independent and optional: absent means the defaults (5.4); no block inherits from another (an API with
an internal authority and a public specification would otherwise break).

| Today | Proposed |
|---|---|
| `target.base_url`, `target.path_seed` | unchanged |
| `target.verify_tls` | `target.tls.verify` |
| `target.openapi_spec_url`, `target.openapi_spec_path` | `specification.url`, `specification.path` |
| `target.gateway_adapter` | `gateway.adapter` |
| `target.admin_api_url`, `target.admin_api_headers` | `gateway.admin.url`, `gateway.admin.headers` |
| `target.health_api_url` | `gateway.health.url` |

Old keys are rejected with a message showing the new form.

### 5.2 Timeouts with their connection - decided (owner, 2026-10-14)

The timeouts and retries of a connection belong to it:

| Today | Proposed |
|---|---|
| `execution.connect_timeout`, `execution.read_timeout`, `execution.max_retry_attempts` | `target.connect_timeout`, `target.read_timeout`, `target.max_retry_attempts` |
| `execution.openapi_fetch_timeout_seconds` | `specification.timeout` |
| `target.admin_connect_timeout_seconds`, `target.admin_read_timeout_seconds` | `gateway.admin.connect_timeout`, `gateway.admin.read_timeout` (the health API uses them too, as today) |

`execution` keeps what the run does: `min_priority`, `strategies`, `test_ids`, `fail_fast`.

### 5.3 The TLS block - decided (owner, 2026-10-14)

```yaml
tls:
  verify: true                        # default; false accepts any server certificate (not with ca_bundle)
  ca_bundle: "certs/ca.pem"           # trust only these authorities for this connection
  client_cert: "certs/apiguard.crt"   # mutual TLS: the tool's certificate (PEM)
  client_key: "certs/apiguard.key"    # its private key (PEM), always with client_cert
```

One model for every connection; the tool builds one `ssl.SSLContext` per block, once. Startup checks (exit `10`):
the files exist and are readable PEM; `client_cert` and `client_key` together; `verify: false` with `ca_bundle` is a
contradiction (`verify: false` with a client certificate is allowed: an unverified test server that still asks for
mutual TLS, as `curl -k --cert`). A warning when the private key can be read by other users of the machine
(as SSH does). Paths relative to the working directory. The private key: the configuration holds its path only; the
tool reads the file only to give it to the TLS library, never in logs, reports or evidence.

### 5.4 Default trust - decided (owner, 2026-10-14)

Without `ca_bundle`, the operating system's store (through `truststore`) **in addition to** today's `certifi` list,
as pip does since 24.2: a company authority installed by IT and proxies inspecting HTTPS work, and the tool never
trusts fewer authorities than today (a minimal container without a system store keeps working). With `ca_bundle`,
only those authorities (as `curl --cacert`). `SSL_CERT_FILE` / `SSL_CERT_DIR` no longer change what the tool trusts
(the configuration says it); `HTTPS_PROXY` keeps working. New dependency: `truststore` (MIT, maintained by pip's
maintainers). To verify first in C2: combining the system store and `certifi` in one context.

### 5.5 Specification download - decided (owner, 2026-10-14)

The tool downloads the specification itself, with `specification.tls` and `specification.timeout`, and gives the
text to prance (which accepts a string). The thread used today to impose a timeout on prance goes. Limit, documented:
external `$ref` to other URLs are still fetched by prance with its defaults. `generate-seed` uses the same download
and accepts `-c config.yaml` to take the `specification` connection (the plain URL argument stays for quick use).

### 5.6 External TLS tests - decided (owner, 2026-10-14)

testssl.sh (`--add-ca`) and sslyze (`custom_ca_file`) receive `target.tls.ca_bundle` when set, and the report states
it ("certificate trust established through the configured authority, not the public ones"). Without `ca_bundle`
they judge with their defaults, as today. Changes their results on the labs (trust findings go, the note comes). An authority installed only in the operating system, without `ca_bundle`, does not change their judgement: their job is to judge the certificate as the world sees it; only an explicit `ca_bundle` changes it, and the report says so.

### 5.7 Errors and edge cases - decided (owner, 2026-10-14)

Failures examined for every connection: untrusted authority, wrong name on the certificate (an IP called, a host name
certified), expired or not yet valid, client certificate missing or refused, only old TLS versions on the server, a
`tls` block on an `http://` URL.

| Failure | Admin / health API | Specification | API |
|---|---|---|---|
| Configuration (files, pairs, contradiction, encrypted key, certificate and key not matching) | stop at startup, exit `10` | stop at startup, exit `10` | stop at startup, exit `10` |
| Certificate or handshake failure | the audits SKIP ("not accessible") with the reason; the other tests run | stop, exit `10` | stop at startup (preflight request), exit `10` |

Rules:

- **No retry of certificate failures.** httpx reports them as `ConnectError`, which the client retries as transient
  (`src/core/client.py`, `RETRYABLE_EXCEPTIONS`); they are recognised and not retried.
- **Preflight request to the API** at startup, with `target.tls`: a certificate failure stops the run once, instead of
  every test returning ERROR; any HTTP answer lets the run go on. Recorded in the evidence (phase "preflight"), as every
  request sent to the target.
- **No password prompt.** An encrypted private key would make Python's TLS library ask for a password on the terminal
  (a CI job would hang): the tool never lets it ask, and stops at startup ("encrypted keys are not supported yet").
- **Contexts built at startup**, so a certificate and a key that do not match fail before any test.
- **Warning** for a `tls` block on an `http://` URL (ignored).
- **Messages** name what happened and the key to set, e.g. "the server's certificate is not trusted (issued by
  "Lab CA"): set `gateway.admin.tls.ca_bundle`"; "the gateway refused the tool's client certificate"; "the server's
  certificate expired on 2026-11-03"; "the certificate is for gw-admin.internal, not 10.0.0.5".
- **Paths** are resolved to absolute ones at load time (external tools run in their own process).

Considered and left out (each can be added later without changing the shape): revocation checks (OCSP/CRL; testssl
reports revocation), pinning, a minimum TLS version enforced by the connection (checking versions is the tests' job),
encrypted keys, a proxy per connection, `validate-config` trying every connection (the preflight covers the API).

### 5.8 Lab PKI - decided (owner, 2026-10-14)

`test-environments/pki/`, shared by the three labs (one company authority signs every service):

| File | What | Validity | Read by |
|---|---|---|---|
| `ca.crt` | the lab authority (`basicConstraints CA:true`, `keyUsage keyCertSign`) | 10 years | the tool (`ca_bundle`), APISIX (client certificates) |
| `ca.key` | its key, used only to sign | 10 years | nobody after generation (`600`) |
| `server.crt`, `server.key` | the gateways' certificate, names `localhost` and `127.0.0.1`, `extendedKeyUsage serverAuth` | 180 days | Kong and APISIX (proxy and Admin API) |
| `client.crt`, `client.key` | the tool's certificate, name `apiguard`, `extendedKeyUsage clientAuth` | 180 days | the tool and `apisix-setup` (mTLS); key `600` |

- 180 days: the CA/Browser Forum limits public server certificates to 200 days from March 2026, shorter in later
  years; testssl flags longer ones today (`cert_extlifeSpan`). Renewed automatically when fewer than 30 days remain.
- Generated by a one-shot container at the start of any lab, with the lab's gateway image (Kong 3.9.3 and APISIX
  3.19.0 ship `openssl`, checked: no new image), running `test-environments/pki/gen-pki.sh`; it does nothing when the
  files exist and are valid; the gateway starts after it; a lock on the folder makes two labs started together
  generate once.
- The folder exists in the repository (the script and a `.gitignore` excluding everything else), so it belongs to who
  cloned the project: Docker would create a missing bind-mount folder as root. The script gives the files to the
  folder's owner; the server key stays readable by the gateways' users (Kong runs as uid 1001), lab only.
- Removed: the committed lab certificate and private key (`test-environments/forgejo-kong/certs/`) and
  `gen-certs.sh`. No private key in the repository.
- The tool's lab configurations trust the lab authority (`ca_bundle: test-environments/pki/ca.crt`).

### 5.9 Labs at the maximum - decided (owner, 2026-10-14)

| | Forgejo + Kong | crAPI + Kong | Forgejo + APISIX |
|---|---|---|---|
| API | HTTPS verified | HTTPS verified | HTTPS verified |
| Specification | HTTPS verified, through the gateway (5.10) | local file | HTTPS verified, through the gateway (5.10) |
| Admin API | HTTPS verified (8444; 8001 kept) | HTTPS verified (9444; 9001 kept) | HTTPS + mTLS + key (one listener) |
| Admin API reachable from | 127.0.0.1 only | 127.0.0.1 only | 127.0.0.1 only (as today) |

Lower levels by changing configuration lines, described in comments in each lab configuration (APISIX: lowering the
Admin API means changing APISIX's configuration). Negative checks in scratch: no authority, wrong authority, no
client certificate, readable key, encrypted key, `tls` on an `http://` URL, plain HTTP; later in the E2E suite (Q-51). `apisix-setup` writes APISIX's configuration over the Admin API with the client certificate and the `admin` key.

### 5.10 Specification over HTTPS, no direct backend access - decided (owner, 2026-10-14)

Facts (2026-10-14): Forgejo serves its specification only at `/swagger.v1.json` on its own port; the gateways route
`/api` only, so through them it answers 404. The Forgejo labs publish Forgejo's port on the host (`3000`, `10003`)
for the specification download and the readiness check: the backend is reachable without the gateway (HTTP, no rate
limit, no gateway headers), a gateway bypass (CWE-288, authentication bypass using an alternate path). The crAPI lab
publishes no service port ("the API is reachable only through Kong").

- The gateways get a route for `/swagger.v1.json` only; the tool downloads the specification from
  `https://localhost:8443/swagger.v1.json` (APISIX: `10443`), verified with the lab authority (publishing the
  specification on the gateway is common in production).
- Forgejo's port is no longer published: the backend is reachable only through the gateway and, on the internal
  network, by the setup containers (`http://forgejo:3000`). The readiness checks go through the gateway.
- Forgejo's `ROOT_URL` becomes the gateway's address (`https://localhost:8443/`, APISIX `https://localhost:10443/`):
  the links in its answers point to the public address, as in production.
- Results to check with the runs (a route more on the gateways, different links in some answers); every difference
  explained.
- Not in this work: a test "the backend is reachable only through the gateway" (the methodology has none; recorded in
  the roadmap and in Q-32).

### 5.11 Documentation - decided (owner, 2026-10-14)

Every command written in a guide is run as written first.

| Document | What |
|---|---|
| `docs/reference/configuration.md` | the sections `target`, `specification`, `gateway`, the `tls` block, the table old key -> new key |
| `docs/guides/usage/configure-a-target.md` | a "TLS and certificates" section: the concepts of section 2; where the files come from (the IT team's authority, or extracted with a given `openssl` command; the client certificate from who runs the gateway); converting a `.p12` to PEM; keys in CI (secret manager, `600`, never in a repository); every error message and what to do |
| `docs/guides/integration/integrate-apiguard.md` | certificates and keys when the tool runs inside another product |
| `docs/reference/report-schema.md`, interface stability in `compatibility.md` | the connection trust of 5.12 (a field added: minor change of the report contract) |
| `docs/reference/compatibility.md` | which protection level is verified on which lab, with sources |
| `docs/architecture/overview.md`, `security-model.md` | the connection model; certificate trust and private-key handling |
| test pages 1.5, ext.1.5.testssl, ext.1.5.sslyze | the API connection; the configured authority given to the external tools |
| `docs/project/maintainer-commands.md` | ports, the lab PKI, regenerating certificates, readiness checks through the gateway |
| `config.example.yaml` | the new structure, commented (checked by `dev:check`) |
| `CHANGELOG.md` | Breaking (keys moved, `verify_tls` replaced, system authorities trusted); changed results (external TLS tests with the authority, the specification route) |
| `CLAUDE.md` | the configuration structure |

### 5.12 The report states how each connection was trusted - decided (owner, 2026-10-14)

For each connection the report states how its certificate was checked: verified with the system's authorities,
verified with `ca_bundle`, or **not verified** (`verify: false`), and whether a client certificate was used. A run
whose API certificate was not verified did not know whether it talked to the right server: the reader must see it.

## 6. Implementation steps

| Step | What | Check |
|---|---|---|
| C1 | Configuration by connection (5.1, 5.2): new sections, old keys rejected with the new form | `dev:check`; three labs identical after converting their configurations |
| C2 | TLS model and contexts (5.3, 5.4); `truststore` | `validate-config` on good and broken blocks |
| C3 | TLS on every connection: API (preflight, no retry of certificate failures), 1.5 probe, specification download by the tool (5.5), `generate-seed`, Admin and health API (5.7); the report states each connection's trust (5.12) | three labs identical; negative checks of 5.7 in scratch |
| C4 | External TLS tests with the authority (5.6) | expected changes only, explained |
| C5 | Lab PKI, labs at the maximum (5.8-5.10) | rebuilt from scratch; full runs; negative checks in scratch |
| C6 | Documentation, `config.example.yaml`, CHANGELOG | key check; docs match the runs |
