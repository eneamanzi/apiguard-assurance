# Security Model

> **Audience:** integrators, operators, contributors · **Status:** v0.1.0 · **Source of truth:** `src/cli.py`, `src/config/loader.py`, `src/core/client.py`,
> `src/core/models/http.py`, `src/core/evidence.py`, `src/core/gateway/kong.py`, `src/connectors/`,
> `src/report/renderer.py`, `src/core/tls.py` · **Verified:** 2026-10-15 (TLS), 2026-10-05

How the tool treats secrets, the target and its own outputs. The tool sends attack traffic: run it only against
systems you are authorised to test.

## Secrets

| Aspect | Behaviour |
|---|---|
| Source | `${VAR}` placeholders in `config.yaml`, resolved from the environment; `.env` is loaded first (the working directory's, or `--env-file`) and never overrides variables already set ([`reference/configuration.md`](../03-reference/01-configuration.md#loading-rules)). |
| Missing variable | Phase 1 stops with exit 10 and names the variable (not its value). |
| Literal values | Nothing prevents writing a password directly in `config.yaml`; placeholders are a convention. |
| Logs | Log events carry identifiers, methods, paths and status codes; the HTTP client does not log headers or bodies, even at `debug` level. Credential values are not logged by the tool's code (checked by searching all log calls). |
| Token storage | Tokens live in memory (`TestContext`) for the run only. |

## Outputs

`evidence.json` and `apiguard_report.json` (and the HTML report) contain request and response data:

- **secret values are replaced with typed placeholders** (`src/core/redaction.py`): only the value is hidden,
  never what proves a finding, and the placeholder keeps the meaning (`[REDACTED: user_a token]`). Details in
  [evidence format](../03-reference/05-evidence-format.md#sensitive-data);
- custom API-key headers and response bodies are kept as received (a body is often the proof itself), apart from
  the secrets registered by the tool;
- the passwords and configured tokens of `credentials`, and every credential the authentication methods obtain,
  are registered as secrets before any request;
- token-acquisition requests of the authentication methods are not recorded;
- external-tool artefacts are sanitised for credentials before storage;
- test 6.4 masks the secrets it finds in the finding detail (first and last characters kept);
- `config_used.yaml` holds no value from the environment and no secret: placeholders stay as written, a secret
  written in clear becomes a placeholder named after its key (fields marked `SECRET_VALUE`,
  [configuration](../03-reference/01-configuration.md#the-configuration-a-run-used-config_usedyaml)).

Treat all output files as sensitive: response bodies can carry the target's data. The HTML report is rendered with Jinja2 autoescaping on HTML and
`StrictUndefined`, so target-controlled strings (e.g. response bodies) are escaped.

## Traffic towards the target

- All requests to the API go through `SecurityClient`: no redirects followed, transport-error retries only.
- Native tests do not start subprocesses; external tools run through connectors.
- Several tests send **write methods** (`POST`, `PUT`, `PATCH`, `DELETE`) without credentials, or create objects
  with valid credentials; the exact behaviour is on each test page under "Prerequisites and effects on the target".
  By design the tool targets only volatile test resources it can lose and does not restore deleted ones (the
  environment does): see design decisions [D6](05-design-decisions.md#d6-prepared-resources) and
  [D10](05-design-decisions.md#d10-path_seed-makes-paths-routable-not-objects-specific).
- Test 4.1 sends a burst of up to 300 requests (default) and exhausts the rate-limit budget of the tool's IP.
- Resources created by tests and the login method (prepared resources with a delete request) are registered for
  teardown and deleted in Phase 6, also after Ctrl+C. Test 7.2 without `url_accepting_endpoint.resource` registers nothing.

## TLS

**Certificate trust.** Every connection (the API, the specification download, the Admin API, the health interface)
checks the server's certificate with its own `tls` block (`src/core/tls.py`):

- by default the operating system's store (through `truststore`, so a company authority installed by IT and a proxy
  inspecting HTTPS are trusted) plus certifi's list; `SSL_CERT_FILE` / `SSL_CERT_DIR` do not change it;
- with `ca_bundle`, only the authorities in that file: a connection to an internal server does not also trust every
  public authority;
- with `verify: false`, nothing is checked: the report shows that connection as **not verified** (red in the HTML
  report, `not_verified` in the JSON report), because the run cannot know it talked to the right server.

A TLS failure is never retried, and on the API it stops the run before any test (preflight, exit 10): an attacker
in the middle, or a wrong configuration, does not produce a report of results against the wrong server. The HTTP
redirect probe of test 1.5 uses the API's context.

**Client certificates and private keys** (mutual TLS):

- only the paths are configuration; the key's content is read by the TLS library and never logged or written to the
  evidence or the reports;
- an encrypted key is refused (exit 10): the tool never prompts for a password, which would hang a CI job;
- a key readable by other users of the machine logs a warning (`chmod 600`);
- keys belong outside the repository; in CI, in the secret manager, written to a `600` file at job start, with the
  path given through `${VAR}` ([configure a target](../02-guides/01-usage/01-configure-a-target.md#2-tls-and-certificates)).

**The Admin API** is called with the headers of `gateway.admin.headers` (values registered as secrets, masked in
every output) and with the context of `gateway.admin.tls`. The health interface (`gateway.health.url`, the APISIX
Control API) is read without those headers: it has no authentication of its own, and the key is not sent where it is
not needed.

**External TLS tools** (testssl.sh) receive the path of `target.tls.ca_bundle` (`--add-ca`), never the client
certificate or its key; their result then notes that the chain was trusted through the configured authority.

**Lab certificates.** The labs' authority and certificates are generated at the first start of a lab
(`test-environments/pki/gen-pki.sh`) and never committed; no private key is in the repository.

## External tools

- Commands are run with `subprocess.run` and an argument list (no shell). Binaries are resolved from
  `./tools/<tool>/` or `PATH`.
- Pinned versions are installed by `install_tools.sh`; `expected_version` logs a warning on mismatch.
- `extra_flags` are appended verbatim; they must not contain secrets.
- `dev_mode: true` replays cached tool output instead of running the tool: never use it in a real assessment.

How each tool that a run can execute treats the server's certificate and the run's credentials:

| Tool | Certificate | Credentials |
|---|---|---|
| testssl.sh | the authorities of `target.tls.ca_bundle` through `--add-ca`; its result records that the chain was trusted through them | never: not the client certificate, not its key |
| Schemathesis | verifies, through `--request-tls-verify` set to `target.tls.ca_bundle` when one is configured | unauthenticated run |
| ffuf | **never verifies**: `InsecureSkipVerify` is fixed in ffuf v2.3.0 and it exposes no option to change it | never, precisely because of the line above: the connector would be handing a credential to a connection it cannot authenticate. ffuf sends unauthenticated `GET` only, and every path it reports is requested again by the test with the tool's own verified client |

nuclei's connector sets `-duc` (no update check) and `-ni` (no interactsh out-of-band callbacks, so no traffic to
third parties), but no test uses it, so a run never executes it ([roadmap](../project/roadmap.md)).

## Known gaps

| Gap | Question |
|---|---|
| No password-protected client key, no certificate pinning, no minimum TLS version per connection ([design decisions, D2](05-design-decisions.md#d2-certificate-trust-per-connection)) | - |
| Unauthenticated write requests and leftover objects on the target (accepted by design: volatile test resources only; [D6](05-design-decisions.md#d6-prepared-resources)) | - |

## See also

- [`overview.md`](01-overview.md) · [`assessment-model.md`](03-assessment-model.md)
- [`reference/evidence-format.md`](../03-reference/05-evidence-format.md#sensitive-data)
