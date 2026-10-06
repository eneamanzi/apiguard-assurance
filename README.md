# APIGuard Assurance

Automated security assessment for REST APIs behind an API gateway.

APIGuard Assurance reads the OpenAPI specification of an API, runs a set of security checks against it and
produces a verdict (exit code), an interactive HTML report, a machine-readable JSON report and an archive of the
HTTP transactions that prove each violation.

The checks come from a methodology of 29 security guarantees in 8 domains (inventory, authentication,
authorization, data integrity, availability, visibility, configuration, business logic). Version 0.1.0 implements
15 native tests and 3 tests based on external tools (nuclei, testssl.sh, sslyze), covering 15 guarantees.

**Use it only against systems you are allowed to test.** The tool sends requests without credentials, with
invalid tokens and with SSRF payloads, and some tests create objects on the target
([effects on the target](docs/guides/usage/configure-a-target.md#effects-on-the-target)).

## Status

Version 0.1.0, developed and tested on Linux against Forgejo behind Kong (DB-less). It works on any API described
by Swagger 2.0 or OpenAPI 3.x, but some tests and defaults still assume Forgejo or Kong
([compatibility](docs/reference/compatibility.md)). The interfaces other than the JSON report are not versioned yet.

## Quick start

Requirements: Linux, Python 3.11 to 3.14, [Hatch](https://hatch.pypa.io/), Docker (for the test lab), Git.

```bash
git clone https://github.com/eneamanzi/apiguard-assurance.git
cd apiguard-assurance
hatch run apiguard version
./install_tools.sh
```

Then follow [First assessment](docs/getting-started/first-assessment.md): it starts a local lab (Forgejo + Kong in
Docker), runs the tool against it and shows how to read the result, in about 10 minutes.

Full installation steps, including how to clean up a previous setup: [Installation](docs/getting-started/installation.md).

## Everyday commands

| Task | Command |
|---|---|
| Check the configuration | `hatch run apiguard validate-config` |
| Run an assessment | `hatch run apiguard run` |
| Use another configuration file | `hatch run apiguard run -c my-api.yaml` |
| List the path parameters of a specification | `hatch run apiguard generate-seed <spec-url-or-file>` |

Exit codes: `0` no violation, `1` at least one violation, `2` a check could not complete, `10` the assessment did not
run ([details](docs/reference/exit-codes.md)).

## Documentation

Start at the [documentation map](docs/index.md). The main entry points:

| I want to… | Read |
|---|---|
| Try the tool | [Installation](docs/getting-started/installation.md), [First assessment](docs/getting-started/first-assessment.md) |
| Run it on my API | [Configure a target](docs/guides/usage/configure-a-target.md), [Select tests](docs/guides/usage/select-tests.md), [Read the report](docs/guides/usage/read-the-report.md) |
| Know what each test checks | [Test catalogue](docs/tests/README.md) |
| Look up a parameter, command or file format | [Configuration](docs/reference/configuration.md), [CLI](docs/reference/cli.md), [Report schema](docs/reference/report-schema.md), [Exit codes](docs/reference/exit-codes.md) |
| Understand how it works | [Architecture](docs/architecture/overview.md) |
| Add a test or support another gateway | [Add a native test](docs/guides/extending/add-a-native-test.md), [Add an external test](docs/guides/extending/add-an-external-test.md), [Add a gateway adapter](docs/guides/extending/add-a-gateway-adapter.md) |

To work on the tool itself: [CONTRIBUTING.md](CONTRIBUTING.md). Changes between versions: [CHANGELOG.md](CHANGELOG.md).
