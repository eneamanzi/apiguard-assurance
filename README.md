# APIGuard Assurance

Automated security assessment for REST APIs behind an API gateway.

APIGuard Assurance reads the OpenAPI specification of an API, runs a set of security checks against it and
produces a verdict (exit code), an interactive HTML report, a machine-readable JSON report and an archive of the
HTTP transactions that prove each violation.

The checks come from a methodology of security guarantees in 8 domains (inventory, authentication,
authorization, data integrity, availability, visibility, configuration, business logic). The tool implements 29
native tests and 3 tests based on external tools (ffuf, testssl.sh, Schemathesis); the full list is in the
[test catalogue](docs/05-tests/README.md).

**Use it only against systems you are allowed to test.** The tool sends requests without credentials, with
invalid tokens and with SSRF payloads, and some tests create objects on the target
([effects on the target](docs/02-guides/01-usage/01-configure-a-target.md#effects-on-the-target)).

## Status

Released: 0.1.0 (2026-05-18); the current version is unreleased, after the block-6 test review that rebuilt and
extended the test suite. Developed and tested on Linux. It works on any API described by Swagger 2.0 or OpenAPI 3.x
and is tested on three labs (Forgejo behind Kong, OWASP crAPI behind Kong, Forgejo behind Apache APISIX); it reads
the gateway configuration of Kong and APISIX, and authenticates with HTTP Basic, a static token, a JSON login or
the Forgejo token API, sending the credential as the specification declares. What each test needs from a target is
in [compatibility](docs/03-reference/06-compatibility.md). The interfaces other than the JSON report are not
versioned yet.

## Quick start

Requirements: Linux, Python 3.11 to 3.14, [Hatch](https://hatch.pypa.io/), Docker (for the test lab), Git.

```bash
git clone https://github.com/eneamanzi/apiguard-assurance.git
cd apiguard-assurance
hatch run apiguard version
./install_tools.sh
```

Then follow [First assessment](docs/01-getting-started/02-first-assessment.md): it starts a local lab (Forgejo + Kong in
Docker), runs the tool against it and shows how to read the result, in about 10 minutes.

Full installation steps, including how to clean up a previous setup: [Installation](docs/01-getting-started/01-installation.md).

## Everyday commands

| Task | Command |
|---|---|
| Check the configuration | `hatch run apiguard validate-config -c test-environments/forgejo-kong/config.yaml` |
| Run an assessment | `hatch run apiguard run -c test-environments/forgejo-kong/config.yaml` |
| Start a configuration for your API | copy `config.example.yaml` (every key, with its description) |
| Use another configuration file | `hatch run apiguard run -c my-api.yaml` |
| List the path parameters of a specification | `hatch run apiguard generate-seed <spec-url-or-file>` |

Exit codes: `0` no violation, `1` at least one violation, `3` a check could not complete, `10` the assessment did not
run ([details](docs/03-reference/03-exit-codes.md)).

## Documentation

Start at the [documentation map](docs/index.md). The main entry points:

| I want to… | Read |
|---|---|
| Try the tool | [Installation](docs/01-getting-started/01-installation.md), [First assessment](docs/01-getting-started/02-first-assessment.md) |
| Run it on my API | [Configure a target](docs/02-guides/01-usage/01-configure-a-target.md), [Select tests](docs/02-guides/01-usage/02-select-tests.md), [Read the report](docs/02-guides/01-usage/03-read-the-report.md) |
| Integrate it into another product or a pipeline | [Integrate APIGuard Assurance](docs/02-guides/02-integration/01-integrate-apiguard.md) |
| Know what each test checks | [Test catalogue](docs/05-tests/README.md) |
| Look up a parameter, command or file format | [Configuration](docs/03-reference/01-configuration.md), [CLI](docs/03-reference/02-cli.md), [Report schema](docs/03-reference/04-report-schema.md), [Exit codes](docs/03-reference/03-exit-codes.md) |
| Understand how it works | [Architecture](docs/04-architecture/01-overview.md) |
| Add a test or support another gateway | [Add a native test](docs/02-guides/03-extending/02-add-a-native-test.md), [Add an external test](docs/02-guides/03-extending/03-add-an-external-test.md), [Add a gateway adapter](docs/02-guides/03-extending/04-add-a-gateway-adapter.md) |

To work on the tool itself: [CONTRIBUTING.md](CONTRIBUTING.md). Changes between versions: [CHANGELOG.md](CHANGELOG.md).
