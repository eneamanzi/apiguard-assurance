# Security Model

> **Audience:** integrators, operators, contributors · **Status:** v0.1.0, several open points (see
> `OPEN_QUESTIONS.md`) · **Source of truth:** `src/cli.py`, `src/config/loader.py`, `src/core/client.py`,
> `src/core/models/http.py`, `src/core/evidence.py`, `src/core/gateway/kong.py`, `src/connectors/`,
> `src/report/renderer.py` · **Verified:** 2026-10-05

How the tool treats secrets, the target and its own outputs. The tool sends attack traffic: run it only against
systems you are authorised to test.

## Secrets

| Aspect | Behaviour |
|---|---|
| Source | `${VAR}` placeholders in `config.yaml`, resolved from the environment; `.env` is loaded first (the working directory's, or `--env-file`) and never overrides variables already set ([`reference/configuration.md`](../reference/configuration.md#loading-rules)). |
| Missing variable | Phase 1 stops with exit 10 and names the variable (not its value). |
| Literal values | Nothing prevents writing a password directly in `config.yaml`; placeholders are a convention. |
| Logs | Log events carry identifiers, methods, paths and status codes; the HTTP client does not log headers or bodies, even at `debug` level. Credential values are not logged by the tool's code (checked by searching all log calls). |
| Token storage | Tokens live in memory (`TestContext`) for the run only. |

## Outputs

`evidence.json` and `apiguard_report.json` (and the HTML report) contain request and response data:

- the `authorization` request header is always replaced with `[REDACTED]`, enforced by the `EvidenceRecord` model;
- **no other header is redacted** (`cookie`, custom API-key headers) and bodies are stored as sent and received;
- token-acquisition requests of the authentication helpers are not recorded;
- external-tool artefacts are sanitised for credentials before storage;
- test 6.4 quotes any secret it finds in the finding detail.

Treat all output files as sensitive (Q-31). The HTML report is rendered with Jinja2 autoescaping on HTML and
`StrictUndefined`, so target-controlled strings (e.g. response bodies) are escaped.

## Traffic towards the target

- All requests to the API go through `SecurityClient`: no redirects followed, transport-error retries only.
- Native tests do not start subprocesses; external tools run through connectors.
- Several tests send **write methods** (`POST`, `PUT`, `PATCH`, `DELETE`) without credentials, or create objects
  with valid credentials; the exact behaviour is on each test page under "Prerequisites and effects on the target".
  Summary and open decisions: Q-30.
- Test 4.1 sends a burst of up to 300 requests (default) and exhausts the rate-limit budget of the tool's IP.
- Resources created by tests are registered for teardown and deleted in Phase 6, also after Ctrl+C. Test 7.2 in
  `fixed_path` mode registers nothing.

## TLS

- `target.verify_tls` (default `true`) controls certificate verification towards `base_url` and the HTTP-redirect
  probe of test 1.5. Set it to `false` only for lab gateways with self-signed certificates.
- The gateway Admin API is always called with certificate verification on and without credentials (Q-34).

## External tools

- Commands are run with `subprocess.run` and an argument list (no shell). Binaries are resolved from
  `./tools/<tool>/` or `PATH`.
- Pinned versions are installed by `install_tools.sh`; `expected_version` logs a warning on mismatch.
- nuclei runs with `-duc` (no update check) and `-ni` (no interactsh out-of-band callbacks, so no traffic to third
  parties).
- `extra_flags` are appended verbatim; they must not contain secrets.
- `dev_mode: true` replays cached tool output instead of running the tool: never use it in a real assessment.

## Known gaps

| Gap | Question |
|---|---|
| Admin API authentication and custom TLS not supported | Q-34 |
| Only `authorization` is redacted in outputs | Q-31 |
| Unauthenticated write requests and leftover objects on the target | Q-30 |
| sslyze dependency is AGPL v3 | Q-11 |

## See also

- [`overview.md`](overview.md) · [`assessment-model.md`](assessment-model.md)
- [`reference/evidence-format.md`](../reference/evidence-format.md#sensitive-data)
